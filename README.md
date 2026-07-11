# 🗂️ Project Casefile

**AI-Powered SOAR Pipeline: From Detection to Documented Response**

![Status](https://img.shields.io/badge/status-v0.5%20complete-brightgreen)
![Wazuh](https://img.shields.io/badge/Wazuh-4.12-blue)
![n8n](https://img.shields.io/badge/n8n-orchestration-orange)
![DFIR--IRIS](https://img.shields.io/badge/DFIR--IRIS-case%20management-green)
![Claude](https://img.shields.io/badge/Claude-AI%20triage-purple)

---

## 📌 Description

Project Casefile is an end-to-end Security Orchestration, Automation, and Response (SOAR) pipeline built in a homelab environment. Wazuh detections are automatically triaged by an AI agent, converted into fully-documented investigation cases in DFIR-IRIS (complete with IOC artifacts, MITRE ATT&CK mappings, and initial analyst notes), and closed out with **human-approved** active response actions — blocking attacker IPs or disabling compromised accounts.

**The problem:** SOC analysts drown in raw alerts. Most pipelines stop at notification ("send it to Slack"). Real incident response requires case management, documentation, and controlled response actions.

**The solution:** A pipeline where every high-severity detection becomes a structured case with AI-generated L1 triage — and where response actions execute only after explicit analyst approval, keeping a human in the loop.

> ⚠️ **Design principle: No automated action ever fires without analyst approval.**


> 📊 **Validated (v0.5):** Wazuh alert → fully-documented IRIS case (AI verdict + MITRE mapping + IOCs) in **~7s average** (n=4). L1 triage accuracy: **3/4 agreement** with analyst ground truth across 2 ATT&CK techniques — the one miss was an AI *under-escalation* caught by the human-in-the-loop gate. Full breakdown in [`validation/metrics.md`](validation/metrics.md).

---

## 🏗️ Architecture

```
┌──────────────┐      ┌───────────────┐      ┌───────────────┐       ┌──────────────┐
│  Endpoints        │───▶│Wazuh Manager        │───▶  │  n8n Webhook      │────▶│ Claude Triage     │
│ (agents)          │      │ rule.level ≥7       │      │ dedupe/parse        │       │ verdict+IOCs      │
└──────────────┘      └───────────────┘      └───────────────┘       └──────┬───────┘
                                                                                                  |
                                ┌───────────────────────────────────────────────▼──┐
                                │              DFIR-IRIS Case                                         │
                                │  severity • artifacts • ATT&CK • analyst notes                      │
                                └──────────────────────┬───────────────────────────┘
                                                       │ analyst approves
                                                       ▼
                                ┌──────────────────────────────────────────────────┐
                                │   n8n → Wazuh API → Active Response on agent                        │
                                │        (firewall-drop / disable account)                            │
                                └──────────────────────────────────────────────────┘
```

**Flow:**
1. Wazuh agents detect suspicious activity → manager forwards alerts (level ≥ 7) to n8n via webhook integration
2. n8n parses, deduplicates, and correlates alerts (one brute force ≠ 40 cases)
3. Claude performs L1 triage: verdict (true positive / benign / needs review), MITRE mapping, IOC extraction, written analysis
4. n8n creates the IRIS case with Claude's output attached as artifacts and notes
5. Analyst reviews the case in IRIS → approves response
6. n8n calls the Wazuh API to trigger Active Response on the affected agent
7. Response result is logged back into the IRIS case timeline

---

## 🧰 Tech Stack

| Component | Role | Notes |
|---|---|---|
| **Wazuh 4.12** | SIEM / detection engine + Active Response | Docker deployment |
| **n8n** | SOAR orchestration layer | Webhook ingestion, dedupe logic, API calls |
| **DFIR-IRIS** | Incident response / case management platform | Docker Compose, REST API |
| **Claude API** | L1 triage agent | Structured JSON verdicts |
| **Atomic Red Team** | Attack simulation / validation | Detection & pipeline testing |
| **Docker** | Container runtime | All services containerized |

---

## ✨ Features

- 🔗 **Automated alert-to-case pipeline** — Wazuh detections become structured IRIS cases in under 60 seconds
- 🧠 **AI L1 triage** — verdict, severity, MITRE ATT&CK technique mapping, and initial analyst notes generated per alert
- 🧬 **IOC extraction as artifacts** — IPs, hashes, usernames, and file paths automatically attached to cases
- 🔁 **Alert deduplication & correlation** — repeated alerts from the same source collapse into a single case
- ✅ **Human-in-the-loop response** — analyst approval gate before any Active Response executes
- 🛡️ **Wazuh Active Response** — firewall-drop (IP block) and custom account-disable scripts
- 📜 **Full case timeline** — every automated step logged back into IRIS for audit trail
- 📊 **Measured performance** — triage accuracy and response-time metrics from validation campaigns

---

## 🗺️ Roadmap

| Phase | Scope | Status |
|---|---|---|
| **v0.1** | DFIR-IRIS deployment, API exploration, manual case flow | ✅ Complete |
| **v0.2** | Wazuh → n8n → IRIS ingestion with dedupe & severity mapping | ✅ Complete |
| **v0.3** | Claude L1 triage layer (verdicts, IOCs, analyst notes) | ✅ Complete |
| **v0.4** | Human-in-the-loop Active Response (firewall-drop, account disable) | ✅ Complete |
| **v0.5** | Validation + metrics: detection-to-case timing, triage accuracy vs. analyst ground truth | ✅ Complete |

---

## 📁 Project Structure

```
project-casefile/
├── README.md
├── docs/
│   ├── architecture.md
│   ├── CASE_STUDY_<name>.md        # deep-dive incident walkthrough
│   └── screenshots/
├── n8n/
│   ├── workflows/
│   │   ├── wazuh-to-iris.json      # ingestion + dedupe workflow
│   │   ├── claude-triage.json      # AI triage sub-workflow
│   │   └── active-response.json    # approval → AR workflow
│   └── README.md
├── wazuh/
│   ├── ossec-integration.conf      # webhook integration block
│   ├── active-response/
│   │   ├── disable-account.sh      # custom AR script
│   │   └── ar-config.conf          # AR command/config blocks
│   └── custom-rules/
├── iris/
│   ├── docker-compose.yml
│   └── api-examples/               # Postman collection / curl examples
├── triage/
│   ├── prompt-schema.md            # Claude triage prompt + JSON schema
│   └── sample-outputs/
└── validation/
    ├── atomic-tests.md             # techniques run + results
    └── metrics.md                  # accuracy & timing tables
```

---

## ⚙️ Setup & Installation

### Prerequisites
- Existing Wazuh 4.12 deployment (Docker)
- n8n instance (Docker)
- Anthropic API key
- ~2 GB free RAM for IRIS + database

### 1. Deploy DFIR-IRIS
```bash
git clone https://github.com/dfir-iris/iris-web.git
cd iris-web
cp .env.model .env        # set passwords, secrets
docker compose up -d
```
Access at `https://<host>:443`, generate an API key under **My Settings → API Key**.

### 2. Configure Wazuh webhook integration
Add to `ossec.conf` on the manager:
```xml
<integration>
  <name>custom-n8n</name>
  <hook_url>http://<n8n-host>:5678/webhook/wazuh-casefile</hook_url>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```
Restart the manager.

### 3. Import n8n workflows
Import the JSON files from `n8n/workflows/` and set credentials for the IRIS API, Claude API, and Wazuh API.

### 4. Configure Active Response
Deploy scripts from `wazuh/active-response/` to agents and add the command/AR blocks to the manager config. *(Detailed steps in phase v0.4 docs.)*

---

## 📐 Detection & Response Rules

*Custom Wazuh rules and Active Response configurations used in this project.*

| Rule / AR | Purpose | MITRE |
|---|---|---|
| _TBD in v0.2_ | | |

Active Response commands:
| Command | Action | Trigger |
|---|---|---|
| `firewall-drop` | Block source IP via iptables | Analyst approval |
| `disable-account` | Disable local user account | Analyst approval |

---

## 🤖 AI Triage Agent

Claude receives the normalized alert JSON and returns a structured verdict:

```json
{
  "verdict": "true_positive | benign | needs_review",
  "severity": "critical | high | medium | low",
  "mitre": ["T1110.001"],
  "iocs": [
    {"type": "ip", "value": "x.x.x.x"},
    {"type": "user", "value": "..."}
  ],
  "analysis": "Initial analyst notes...",
  "recommended_action": "..."
}
```

The verdict drives routing: `benign` alerts are auto-closed with a note; `true_positive` and `needs_review` become IRIS cases with IOCs attached as artifacts.

### 📊 Triage Metrics *(populated in v0.5)*

| Metric | Result |
|---|---|
| Alert → documented case time | _TBD_ |
| Triage accuracy (vs. manual verdict) | _TBD_ |
| False positive suppression rate | _TBD_ |
| Approval → response execution time | _TBD_ |

---

## 🏠 Homelab Environment

| VM | IP | Role |
|---|---|---|
| ubuntuai | 192.168.248.20 | Wazuh manager, n8n, DFIR-IRIS (Docker) |
| ubuntu-webserver | 192.168.248.139 | Wazuh agent / target |
| Windows 11 | 192.168.248.128 | Wazuh agent / target |
| Kali Linux | 192.168.248.130 | Attacker box (Atomic Red Team, brute force) |

VMware Workstation, dual-interface netplan (NAT + host-only), all services containerized.

---

## 🔐 Security Notes

- All API keys and secrets stored in `.env` files — **never committed** (see `.gitignore`)
- IRIS default credentials rotated on first boot
- Active Response scripts require analyst approval via the n8n gate — no autonomous blocking
- Homelab is fully isolated on host-only networking; attack traffic never leaves the lab
- Alert data sent to the Claude API contains lab-only IPs and synthetic accounts

---

## 👤 Author

**Eliezer Fuentes**
Cybersecurity professional — SOC analysis, detection engineering, vulnerability management
GitHub: [@enak223](https://github.com/enak223) • LinkedIn: [eliezerfuentes](https://linkedin.com/in/eliezerfuentes)

Related projects: [Tripwire](https://github.com/enak223/project-tripwire) • [GhostNet](https://github.com/enak223/project-ghostnet) • [NullByte](https://github.com/enak223/project-nullbyte) • [Watchtower](https://github.com/enak223/project-watchtower)

---

 ## 🗃️ Quote

> *"Alerts tell you something happened. Cases tell you what you did about it."*
