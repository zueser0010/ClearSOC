# ClearSOC — Security Operations Centre Simulation Platform

A web-based SOC analyst training and simulation platform built on real Wazuh SIEM telemetry. ClearSOC ingests Windows Security Event logs and Sysmon data, applies custom MITRE ATT&CK-mapped detection rules, correlates related alerts into multi-stage attack chains, and guides analysts through a structured 3-step investigation workflow.

Built as a final-year BSc Cybersecurity project at LSBF Singapore / University of East London.

---

## What It Does

- **Real detection pipeline** — custom rules covering 8+ ATT&CK techniques (T1110 Brute Force, T1059 PowerShell, T1543.003 Persistence, T1550.002 Pass-the-Hash, T1562.002 Defense Evasion, T1087 Discovery, T1105 Malware Drop, T1078 Valid Accounts)
- **Attack chain correlation** — groups related alerts by host/user, assigns weighted risk score, severity and recommended decision (Escalate / Investigate / Monitor)
- **3-step investigation workflow** — Validate & Scope → Detect Persistence & Lateral Movement → Analyst Verdict & Response
- **Evidence Console** — right-panel showing corroborating host alerts, raw event detail, Zeek network context, and FP/TP assessment
- **MITRE ATT&CK coverage map** — 10 techniques detected with plain-English explanations
- **Threat Hunting workspace** — 8 hypothesis-driven hunt templates plus custom search across 26,000+ events
- **Priority Queue** — actionable work list filtered to ESCALATE/INVESTIGATE decisions, ranked by risk score
- **Timeline heatmap** — 60-day activity calendar with drill-down by date

---

## Stack

| Layer | Technology |
|---|---|
| Frontend | React + Vite, Recharts, Lucide React |
| Backend | Python 3, FastAPI |
| Database | SQLite |
| SIEM | Wazuh (manager + agents) |
| Network | Zeek 8.0.5 |
| Lab | VMware: pfSense, Kali, Windows 10, Windows Server 2019, Ubuntu |

---

## Getting Started

### Prerequisites
- Python 3.10+
- Node.js 18+
- Wazuh manager (optional — pre-populated database included)

### Run the backend
```bash
cd backend
pip install -r requirements.txt
python3 soc_pipeline_v2.py        # generate reports from database
uvicorn api_server:app --host 0.0.0.0 --port 8001
```

### Run the frontend
```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173

### Database
The SQLite database (`reports/clearsoc.db`) contains 26,000+ real security events collected from a Windows lab environment under active attack simulation.

The database is included in the submission package but excluded from this repository due to size (60MB). To run ClearSOC with populated data, obtain the database from the submission package and place it at `reports/clearsoc.db`, then run:

````bash
python3 backend/soc_pipeline_v2.py
```

---

## Lab Environment

| Host | IP | Role |
|---|---|---|
| pfSense | 192.168.10.1 | Gateway / Firewall |
| Ubuntu (Wazuh) | 192.168.10.157 | SIEM Manager + ClearSOC host |
| Windows 10 | 192.168.10.x | Endpoint (Wazuh agent + Sysmon) |
| Windows Server 2019 | 192.168.10.145 | Domain Controller (Wazuh agent) |
| Kali Linux | 192.168.10.144 | Attacker machine |

---

## Attack Scenarios Detected

| Scenario | Technique | Chain |
|---|---|---|
| Brute force + successful login | T1110, T1078 | CHAIN-00001 |
| PowerShell execution + persistence + discovery | T1059.001, T1543.003, T1087 | CHAIN-00002 |
| Privilege escalation (leo account) | T1078.002 | CHAIN-00003 |
| Multi-stage execution on win-server | T1059.003, T1543.003 | CHAIN-00004 |
| Pass-the-Hash lateral movement | T1550.002 | CHAIN-00005 |

---

## Project Structure
---

## Author

Alwin Joy — BSc Cybersecurity, LSBF Singapore / University of East London  
Student ID: S1034927  
GitHub: [@zueser0010](https://github.com/zueser0010)  
LinkedIn: [linkedin.com/in/alwin-joy-5bab48323](https://linkedin.com/in/alwin-joy-5bab48323)
