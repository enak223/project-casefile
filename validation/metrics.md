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
