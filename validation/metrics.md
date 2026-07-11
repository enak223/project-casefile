# Casefile v0.5 — Validation Metrics

## Detection-to-Case Timing (automated stages)

Measured from n8n webhook arrival (`Wazuh Alert Webhook` timestamp) to
DFIR-IRIS `alert_creation_time`, same execution ID. Attack: SSH brute-force
(hydra, Kali .130 → ubuntu-webserver), Wazuh rule 5763.

| n8n Execution | IRIS Alert | Webhook Arrival (UTC) | IRIS Alert Created (UTC) | Latency |
|---|---|---|---|---|
| 2632 | 74 | 13:15:30.960 | 13:15:37.113 | 6.15s |
| 2714 | 76 | 15:44:57.210 | 15:45:06.246 | 9.04s |
| 2718 | 77 | 15:50:53.450 | 15:50:59.498 | 6.05s |
| 2724 | 78 | 16:00:37.486 | 16:00:44.131 | 6.65s |

**Average: 6.97s · Median: 6.40s · Range: 6.05–9.04s** (n=4)

### Notes
- ~99% of latency is the Claude triage API call; IRIS ingestion itself is ~56ms
  (`alert_source_event_time` vs `alert_creation_time`, run 2714).
- The 9.04s outlier corresponds to a longer extended-thinking triage response.
- Run 2724 produced a different verdict path (`escalate_to_analyst`, medium
  confidence) vs `block_ip` (0.75) on identical attack traffic — carried
  forward into the triage-accuracy analysis below.

## Triage Accuracy
_TBD — part 2 of v0.5._

## Triage Accuracy (Claude L1 verdict vs. analyst ground truth)

Claude's L1 verdict compared against manual analyst disposition across 4 alerts
spanning 2 techniques. "Agree" = analyst concurs with Claude's verdict + action.

| # | IRIS Alert | Attack | Claude Verdict | Conf. | MITRE | Claude Action | Analyst Verdict | Agree |
|---|---|---|---|---|---|---|---|---|
| 1 | 76 | SSH brute-force | true_positive | 0.75 | T1110 | block_ip | true_positive / block | ✅ |
| 2 | 77 | SSH brute-force | true_positive | 0.75 | T1110 | block_ip | true_positive / block | ✅ |
| 3 | 78 | SSH brute-force | true_positive | med | T1110, T1110.001 | escalate_to_analyst | true_positive / escalate | ✅ |
| 4 | 80 | New local user (T1136.001) | benign | 0.6 | T1136.001 | monitor | **escalate / verify** | ❌ |

**Agreement: 3/4 (75%)**

### Analysis of the disagreement (Alert #80)
- **What Claude did well:** correctly mapped T1136.001 (Persistence / Local
  Account) and ignored the concurrent sudo (T1548.003) and PAM password-change
  noise in the same event burst — it isolated the right technique.
- **Where it erred:** Claude downgraded a level-10 detection to `benign / monitor`
  by inferring from the username (`casefile_test`) that the event was "likely a
  test." A username is attacker-controllable and is not authorization evidence.
- **Correct disposition:** account creation is a change-management event. Absent
  corroboration from an authorization source (onboarding ticket, change request),
  the alert should be **escalated/verified**, not silently monitored.
- **Why this matters:** Claude's miss was an *under-escalation* of a
  security-relevant event — precisely the failure mode the human-in-the-loop
  approval gate exists to catch. In this pipeline, the analyst review step would
  have overridden the AI verdict before any (in)action was finalized.

### Key takeaways for the pipeline
1. **Detection coverage ≠ response coverage.** Rule 101002 fired correctly, but
   the n8n integration originally forwarded only rule_ids 5763,5712 (brute-force).
   The persistence alert was detected by Wazuh yet never triaged until 101002 was
   added to the `<rule_id>` forward list. SIEM visibility and SOAR scope are
   separate coverage problems.
2. **Non-determinism in L1 triage.** Identical brute-force traffic produced two
   different action recommendations (block_ip vs. escalate_to_analyst, runs 76/77
   vs. 78) — reinforcing that AI triage is an assistive layer, not an autonomous
   decision-maker.
3. **Port scans (T1046) are out of scope for host-based detection.** Confirmed
   that Wazuh (HIDS) does not natively detect SYN scans; that capability lives in
   the Suricata-based GhostNet project (NIDS). Casefile's detection surface is
   host logs (auth, audit, PAM, sudo), which correctly bounds what it can triage.
