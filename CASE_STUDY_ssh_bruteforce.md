# 🔒 Case Study: SSH Brute Force → Human-Approved Automated Block

> **Incident ID:** CASEFILE-001
> **Date:** July 10, 2026
> **Analyst:** Eliezer Fuentes
> **Pipeline:** Project Casefile (Wazuh → n8n → Claude → DFIR-IRIS → Human Approval → Wazuh Active Response)
> **Outcome:** Attacker IP dropped at the host firewall following explicit analyst approval — full detection-to-response chain under automation, with a human in the loop.

---

## 📌 Summary

An SSH brute-force attack against the `root` account on `ubuntu-webserver` was detected by Wazuh, automatically triaged by Claude, documented as a case in DFIR-IRIS, escalated to an analyst by email, and — after explicit approval — blocked at the host firewall via Wazuh Active Response. No automated response fired without human sign-off.

This case demonstrates the pipeline answering *"walk me through your incident response process"* with a live, working system rather than a memorized lifecycle: **Detect → Triage → Document → Decide → Respond.**

---

## 🗺️ Incident Timeline

| Time (approx.) | Stage | Actor | Detail |
|---|---|---|---|
| T+0s | Attack | Kali (192.168.248.130) | `hydra` SSH brute force against `root@192.168.248.139` |
| T+~2s | Detection | Wazuh | Rule **5763** (level 10) fires — repeated failed root auth |
| T+~3s | Ingestion | n8n | Alert received via webhook, normalized, severity mapped |
| T+~5s | Triage | Claude | Structured verdict returned: `true_positive`, IOCs extracted, MITRE mapped |
| T+~6s | Case creation | DFIR-IRIS | Alert #_XX_ created with severity, notes, and IOCs |
| T+~6s | Gate | n8n IF node | `needs_approval = yes` (verdict + `iris_severity_id ≥ 5`) → true branch |
| T+~7s | Escalation | n8n → Email | Approval email sent with APPROVE / REJECT links |
| _analyst decision window_ | Wait | n8n Wait node | Execution parked pending human input |
| T+decision | Approval | Analyst | Clicked **APPROVE — Block IP** |
| T+decision+~1s | Auth | n8n → Wazuh API | JWT token obtained (`wazuh-wui`, Basic Auth) |
| T+decision+~2s | Response | Wazuh AR | `firewall-drop` executed on agent 003 |
| T+decision+~3s | Containment | ubuntu-webserver | `iptables` DROP rule inserted for 192.168.248.130 — attacker locked out |

> _Fill exact timestamps from the winning execution (ID#2403) and IRIS alert record._

---

## 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Credential Access | Brute Force | **T1110** | Repeated failed SSH password attempts against `root` |
| Credential Access | Password Guessing | **T1110.001** | Automated `hydra` wordlist run against a single account |

**Response mapped to:** Wazuh Active Response `firewall-drop` (host-based iptables block) — a containment action, analyst-approved.

---

## 🔬 Detection Detail

**Trigger:** Wazuh rule **5763** — *"sshd: brute force trying to get access to the system. Authentication failed."* (level 10)

**Source of truth for severity:** the pipeline gates on the **deterministic** `iris_severity_id` derived from the Wazuh rule level, **not** Claude's self-reported `severity` field. This decision was made because the LLM's severity label drifted between runs (observed `medium` on a level-10 event that should map to High). Gating on the rule-level-derived severity eliminates that drift from the response decision.

```
Attacker: 192.168.248.130 (Kali)
Target:   192.168.248.139 (ubuntu-webserver, agent 003)
Account:  root
Rule:     5763 (level 10)
```

> **📷 Screenshot slot 1 — Detection:** Wazuh alert / `alerts.log` grep showing rule 5763, src IP, user root.

---

## 🤖 AI Triage Output

Claude received the normalized alert and returned a structured verdict:

```json
{
  "verdict": "true_positive",
  "severity": "medium",
  "confidence": 0.75,
  "mitre": ["T1110", "T1110.001"],
  "iocs": [
    { "type": "ip", "value": "192.168.248.130" },
    { "type": "user", "value": "root" }
  ],
  "analysis": "SSH brute-force against the root account from an internal RFC1918 host...",
  "recommended_action": "block_ip"
}
```

The verdict drove routing; the IOCs were written to the IRIS case as artifacts; the analysis became the case notes.

> **📷 Screenshot slot 2 — Triage:** `Build IRIS Payload` output showing the parsed `triage` object and `needs_approval: "yes"`.

---

## 📁 Case Documentation (DFIR-IRIS)

The alert was created as an IRIS case with:
- Severity: **High** (id 5), mapped from Wazuh rule level
- Status: New / unassigned
- Analyst notes: Claude's written analysis
- Tags: `T1110`, `T1110.001`

> **📷 Screenshot slot 3 — IRIS:** the created alert/case record in the IRIS UI.

---

## ✅ The Approval Gate (Human-in-the-Loop)

**Hard rule:** *No response fires without explicit analyst approval.*

The gate condition:

```
needs_approval == "yes"
  where needs_approval = (verdict === "true_positive" && iris_severity_id >= 5) ? "yes" : "no"
```

On a true result, an approval email is sent containing the verdict, severity, source IP, and two links:
- **✅ APPROVE — Block IP** → resumes the workflow, routes to the block action
- **❌ REJECT — No action** → case stays open in IRIS, no response fires

The n8n **Wait** node parks the execution until the analyst clicks. The resume URL carries the decision as a query parameter (`approved=true/false`).

> **📷 Screenshot slot 4 — Approval email:** the received email with APPROVE / REJECT links.

---

## 🚫 The Response (Wazuh Active Response)

On approval, the pipeline:
1. Authenticated to the Wazuh API (`wazuh-wui`, Basic Auth → JWT).
2. Issued `PUT /active-response?agents_list=003` with the block command.
3. Wazuh dispatched `firewall-drop` to agent 003.
4. The agent inserted an `iptables` DROP rule for the attacker IP.

**Working API body (the exact format that the agent script parses):**
```json
{
  "command": "!firewall-drop",
  "alert": { "data": { "srcip": "192.168.248.130" } }
}
```

**Result:** `{"data":{"affected_items":["003"],"total_affected_items":1,...},"error":0}`

> **📷 Screenshot slot 5 — Block IP node output:** `affected_items: ["003"]`, `error: 0`.
> **📷 Screenshot slot 6 — Containment proof:** `iptables -L -n | grep 192.168.248.130` showing DROP rules.
> **📷 Screenshot slot 7 — Full chain:** the complete green n8n execution (Webhook → Block IP).

---

## 📊 Verification

After the block, repeated `hydra` runs from Kali returned:
```
[ERROR] could not connect to ssh://192.168.248.139:22 - Timeout connecting
```
The attacker could no longer reach the target — confirming the containment was effective end to end.

---

## ⚙️ Engineering Notes & Failure Modes

Honest limitations and hard-won lessons from building this chain (documented because they make the system more credible, not less):

- **LLM severity drift.** Claude's `severity` field varied across identical inputs. Mitigated by gating on the deterministic `iris_severity_id` (rule-level-derived) rather than the model's self-report.
- **AR API body format.** The Wazuh agent's `firewall-drop` script reads `srcip` from a **nested** `alert.data.srcip` object. The positional `arguments: ["-", "<ip>", "1"]` form was accepted by the API but failed at the agent with *"Cannot read 'srcip' from data."* The `custom` field is rejected outright by this version.
- **API auth method.** The authenticate endpoint requires **HTTP Basic Auth on a GET**, not a JSON POST body. The `API_PASSWORD` env var is applied only at first container init; the RBAC DB is authoritative thereafter.
- **Resume URL hygiene.** n8n's `$execution.resumeUrl` already includes a `?signature=...` query string, so the decision param must be appended with `&approved=true`, not a second `?`.
- **Credential exposure in logs.** Approving from a browser logged into the Wazuh dashboard attached the Wazuh session cookie (including a live JWT) to the resume request, which n8n logged in the execution data. Mitigation: approve from a clean session or strip cookies.
- **AR timeout behavior.** `<timeout>600</timeout>` reliably removed alert-triggered blocks but manually/API-triggered blocks lingered, requiring manual `iptables -D`.

---

## 🏠 Environment

| Host | IP | Role |
|---|---|---|
| ubuntuai | 192.168.X.X | Wazuh manager + n8n + DFIR-IRIS (Docker) |
| ubuntu-webserver | 192.168.X.X | Victim / Wazuh agent 003 |
| Kali Linux | 192.168.X.X | Attacker |

_IPs obfuscated for public documentation._

---

## 👤 Author

**Eliezer Fuentes** — Cybersecurity Professional

Threat Hunting | Vulnerability Management | SOC Automation | Detection Engineering

[![GitHub](https://img.shields.io/badge/GitHub-enak223-181717?style=flat&logo=github)](https://github.com/enak223)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-eliezerfuentes-0A66C2?style=flat&logo=linkedin)](https://www.linkedin.com/in/eliezerfuentes/)

---

> *"Detection without response is just an alarm. Casefile closes the loop — with a human's hand on the switch."*
