# 🤖 Claude L1 Triage Agent — Prompt Schema

This document defines the prompt, input contract, and output schema for the AI triage layer (Phase v0.3). The goal: Claude behaves like a disciplined L1 analyst — consistent verdicts, structured output, no hallucinated IOCs, and explicit uncertainty when the alert doesn't contain enough evidence.

---

## Design Principles

1. **JSON in, JSON out.** The n8n workflow must be able to parse every response without regex cleanup. The prompt forbids prose outside the JSON object.
2. **Evidence-bound.** Claude may only cite IOCs and facts present in the alert payload. No invented context.
3. **Uncertainty is a valid answer.** `needs_review` exists so the model isn't forced into false confidence — this is what routes to a human.
4. **Deterministic-ish.** Temperature 0, fixed schema, enumerated values only. Same alert should produce the same verdict.
5. **Cheap first, smart second.** n8n filters level < 7 and dedupes *before* calling Claude. The model only sees alerts worth analyzing.

---

## API Call (n8n HTTP Request node)

```json
POST https://api.anthropic.com/v1/messages
{
  "model": "claude-sonnet-4-6",
  "max_tokens": 1500,
  "temperature": 0,
  "system": "<SYSTEM PROMPT — see below>",
  "messages": [
    { "role": "user", "content": "<ALERT PAYLOAD JSON — see Input Contract>" }
  ]
}
```

> n8n gotcha (learned in NullByte): use `JSON.stringify()` in a Code node to serialize the alert before the HTTP Request node, or expression interpolation will mangle nested quotes.

---

## System Prompt

```
You are an L1 SOC analyst performing initial triage on a Wazuh SIEM alert
from an isolated homelab environment. You will receive one alert as JSON.

Your job:
1. Determine a verdict: "true_positive", "benign", or "needs_review".
2. Map the activity to MITRE ATT&CK technique IDs (sub-technique where possible).
3. Extract every IOC present in the alert data.
4. Write concise initial analyst notes (3-6 sentences): what happened, why
   the verdict, what an analyst should check next.
5. Recommend one action from the allowed list.

Rules:
- Respond with ONLY a valid JSON object matching the schema below. No prose,
  no markdown fences, no preamble.
- Only reference IPs, users, hashes, paths, and hostnames that literally
  appear in the alert. Never invent or infer IOC values.
- If the alert lacks enough evidence for a confident verdict, use
  "needs_review" and say what evidence is missing in "analysis".
- "benign" is reserved for clear noise: expected admin activity, known lab
  maintenance, CIS benchmark/config findings with no attack behavior.
- Verdict confidence: if you would not stake your reputation on
  "true_positive" or "benign", choose "needs_review".
- recommended_action must be one of:
  "none", "monitor", "block_ip", "disable_account", "isolate_host",
  "escalate_to_analyst".
- recommended_action is advisory only. A human approves all actions.

Output schema:
{
  "verdict": "true_positive | benign | needs_review",
  "severity": "critical | high | medium | low",
  "confidence": 0-100,
  "mitre": ["T####.###"],
  "iocs": [ { "type": "ip|user|hash|domain|file_path|hostname|process", "value": "..." } ],
  "analysis": "string",
  "recommended_action": "enum above",
  "case_title": "short human-readable title, e.g. 'SSH Brute Force from 192.168.248.130'"
}
```

---

## Input Contract (what n8n sends)

The Code node normalizes the raw Wazuh alert to this shape before the API call — keeps token usage down and gives Claude a stable structure:

```json
{
  "rule": {
    "id": "5763",
    "level": 10,
    "description": "sshd: brute force trying to get access to the system.",
    "mitre": ["T1110"],
    "groups": ["syslog", "sshd", "authentication_failures"]
  },
  "agent": { "id": "002", "name": "ubuntu-webserver", "ip": "192.168.248.139" },
  "timestamp": "2026-07-02T14:31:07.412Z",
  "data": {
    "srcip": "192.168.248.130",
    "srcuser": "root",
    "dstuser": "root"
  },
  "full_log": "Jul  2 14:31:05 ubuntu-webserver sshd[8841]: Failed password for root from 192.168.248.130 port 55012 ssh2",
  "correlation": {
    "duplicate_count": 27,
    "window_minutes": 5,
    "first_seen": "2026-07-02T14:26:12.000Z"
  }
}
```

The `correlation` block is added by the n8n dedupe logic — it tells Claude "this is the 27th identical alert in 5 minutes," which is triage-relevant context the raw alert doesn't carry.

---

## Output Example

```json
{
  "verdict": "true_positive",
  "severity": "high",
  "confidence": 92,
  "mitre": ["T1110.001"],
  "iocs": [
    { "type": "ip", "value": "192.168.248.130" },
    { "type": "user", "value": "root" },
    { "type": "hostname", "value": "ubuntu-webserver" }
  ],
  "analysis": "27 failed SSH authentication attempts targeting the root account on ubuntu-webserver from 192.168.248.130 within a 5-minute window. The volume, single source, and direct root targeting are consistent with automated password guessing rather than user error. No successful authentication is present in this alert; the analyst should query for rule 5715 (successful login) from the same source IP to rule out compromise. Source IP is the lab Kali host, consistent with a simulated attack.",
  "recommended_action": "block_ip",
  "case_title": "SSH Brute Force against root on ubuntu-webserver from 192.168.248.130"
}
```

---

## n8n Routing Logic (post-triage)

| Verdict | Route |
|---|---|
| `benign` | Close IRIS alert with Claude's analysis as the closing note. No case. |
| `needs_review` | Create IRIS **alert** (not case) — analyst promotes manually. |
| `true_positive` + severity `medium/low` | Create IRIS case, attach IOCs as artifacts, no response prompt. |
| `true_positive` + severity `high/critical` | Create case + trigger the approval workflow (v0.4) with `recommended_action`. |

Parsing guard in the Code node:

```javascript
const raw = $json.content.filter(b => b.type === "text").map(b => b.text).join("");
let triage;
try {
  triage = JSON.parse(raw.replace(/```json|```/g, "").trim());
} catch (e) {
  // Schema violation → fail safe: route to needs_review with raw text attached
  triage = { verdict: "needs_review", severity: "medium", confidence: 0,
             mitre: [], iocs: [], analysis: "TRIAGE PARSE FAILURE: " + raw.slice(0, 500),
             recommended_action: "escalate_to_analyst",
             case_title: "Unparseable triage output — manual review" };
}
```

**Fail-safe principle:** a broken AI response must never silently drop an alert. Parse failures route to a human.

---

## Validation Plan (feeds v0.5 metrics)

For each Atomic Red Team run, record:

| Field | How |
|---|---|
| Claude verdict | from JSON output |
| Manual verdict | your own call, made *before* reading Claude's |
| Agreement | match/mismatch |
| IOC completeness | did Claude extract every IOC you found manually? |
| Hallucination check | any IOC value not present in the alert payload? |

Log mismatches in `triage/sample-outputs/` with a one-line note on why Claude was wrong — that error analysis is the v0.5 case-study material and the interview deep-dive.

---

## Known Risks / Tuning Notes

- **Prompt injection via log content:** `full_log` is attacker-influenced text. An attacker could plant instructions in a username or log line. Mitigation: the system prompt's evidence-bound rules, JSON-only output, and — critically — the human approval gate means injected "recommendations" can't execute anything. Document this in the README's Security Notes; it's a sophisticated talking point.
- **Verdict drift on config-type alerts:** Wazuh SCA/rootcheck findings tend to get over-classified as threats. If you see this, add an explicit example to the system prompt.
- **Token cost:** normalized input keeps calls ~500-800 tokens. Don't send `full_log` arrays for correlated alerts — send one representative log plus the correlation counts.
