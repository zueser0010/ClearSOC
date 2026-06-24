import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta

LIVE_WAZUH_RULES = {
    "92021": {
        "title": "PowerShell File Deletion Activity",
        "severity": "MEDIUM",
        "mitre": ["T1070.004"]
    },
    "92031": {
        "title": "Discovery Activity Executed",
        "severity": "MEDIUM",
        "mitre": ["T1087"]
    },
    "92066": {
        "title": "Suspicious PowerShell Child Process",
        "severity": "HIGH",
        "mitre": ["T1059.001"]
    },
    "92205": {
        "title": "PowerShell Created File in Windows Root Folder",
        "severity": "HIGH",
        "mitre": ["T1105"]
    }
}


from detection_packs import run_detection_packs

SEV_TO_BASE_CONFIDENCE = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW"}
CONF_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

def compute_alert_confidence(severity, related_chain):
    base = SEV_TO_BASE_CONFIDENCE.get(severity, "LOW")
    chain_conf = related_chain["confidence"] if related_chain else None
    if chain_conf and CONF_RANK.get(chain_conf, 0) > CONF_RANK.get(base, 0):
        return chain_conf
    return base


REPORTS_DIR = Path("../reports")
RAW_LOGS_FILE = REPORTS_DIR / "raw_logs.json"
SOC_ALERTS_FILE = REPORTS_DIR / "soc_alerts.json"
ATTACK_CHAINS_FILE = REPORTS_DIR / "attack_chains.json"
INVESTIGATIONS_FILE = REPORTS_DIR / "investigations.json"
DASHBOARD_FILE = REPORTS_DIR / "dashboard_data.json"

KILL_CHAIN_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Command and Control"
]

def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def flatten_logs(data):
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ["logs", "events", "data", "raw_logs"]:
            if isinstance(data.get(key), list):
                return [x for x in data[key] if isinstance(x, dict)]
    return []

def parse_time(value):
    if not value or value == "unknown":
        return None
    try:
        fixed = str(value).replace("+0800", "+08:00")
        return datetime.fromisoformat(fixed)
    except Exception:
        return None

def normalize_event(raw):
    def first(paths, default="unknown"):
        for p in paths:
            cur = raw
            for part in p.split("."):
                if not isinstance(cur, dict):
                    cur = None
                    break
                cur = cur.get(part)
            if cur not in [None, "", "-", "unknown", "N/A"]:
                return cur
        return default

    timestamp = first(["timestamp", "time", "@timestamp"])
    host = first(["host", "hostname", "agent_name"])
    user = first(["user", "username"])
    source_ip = first(["source_ip", "src_ip", "agent.ip"], "unknown")
    destination_ip = first(["destination_ip", "dst_ip"], "unknown")
    event_id = str(first(["event_id", "EventID"], ""))
    rule_id = str(first(["rule_id"], ""))
    process = first(["process", "image", "process_name"], "")
    parent_process = first(["parent_process", "parent_image"], "")
    command_line = first(["command_line", "cmdline"], "")
    message = first(["message", "full_log", "rule_description"], "")
    rule_id = str(first(["rule_id"], ""))
    rule_level = first(["rule_level"], 0)
    rule_description = first(["rule_description"], "")

    # Normalize user
    if user and "\\" in str(user):
        user = str(user).split("\\")[-1]
    user = str(user).lower().strip()

    return {
        "timestamp": timestamp,
        "parsed_time": parse_time(timestamp),
        "event_id": event_id,
        "rule_id": rule_id,
        "host": str(host),
        "user": user,
        "source_ip": str(source_ip),
        "destination_ip": str(destination_ip),
        "process": str(process),
        "parent_process": str(parent_process),
        "command_line": str(command_line),
        "message": str(message),
        "rule_id": rule_id,
        "rule_level": rule_level,
        "rule_description": rule_description,
        "raw": raw
    }

def build_alerts(events):
    alerts = []
    for event in events:
        findings = run_detection_packs(event)
        for finding in findings:
            alerts.append({
                "alert_id": f"CSA-{len(alerts)+1:05d}",
                "time": event["timestamp"],
                "host": event["host"],
                "user": event["user"],
                "source_ip": event["source_ip"],
                "destination_ip": event["destination_ip"],
                "event_id": event["event_id"],
                "rule_id": event["rule_id"],
                "rule_description": event["rule_description"],
                "process": event["process"],
                "parent_process": event["parent_process"],
                "command_line": event["command_line"],
                "pack": finding["pack"],
                "rule_name": finding["rule_name"],
                "title": finding["title"],
                "summary": finding["summary"],
                "severity": finding["severity"],
                "mitre": finding["mitre"],
                "kill_chain_phase": finding.get("kill_chain_phase", "Unknown"),
                "recommended_actions": finding["recommended_actions"],
                "fp_notes": finding.get("fp_notes", ""),
                "status": "OPEN",
                "raw": event["raw"]
            })
    return alerts

def severity_rank(sev):
    return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(str(sev).upper(), 1)

def build_attack_chains(alerts):
    # Group by (host, user) only — ignore source_ip
    # Auth events use 127.0.0.1, process events use real IP
    # Grouping by source_ip breaks correlation
    grouped = defaultdict(list)

    for alert in alerts:
        key = (
            alert.get("host", "unknown"),
            alert.get("user", "unknown")
        )
        grouped[key].append(alert)

    chains = []

    for (host, user), group in grouped.items():
        group = sorted(group, key=lambda x: x.get("time") or "")

        if len(group) < 2:
            continue

        packs = set(a["pack"] for a in group)
        event_ids = set(str(a["event_id"]) for a in group)
        kill_chain_phases = []

        for phase in KILL_CHAIN_ORDER:
            if any(a.get("kill_chain_phase") == phase for a in group):
                kill_chain_phases.append(phase)

        # Score the chain
        score = 0
        reasons = []

        failed_count = len([a for a in group if a["event_id"] == "4625"])
        has_success = "4624" in event_ids
        has_privesc = "privilege_escalation" in packs
        has_powershell = "malicious_powershell" in packs
        has_persistence = "persistence" in packs
        has_lateral = "lateral_movement" in packs
        has_cred_dump = "credential_dumping" in packs
        has_brute_success = "brute_force_success" in packs

        if has_brute_success:
            score += 40
            reasons.append("Brute force followed by successful login")
        elif "brute_force" in packs or "authentication_failure" in packs:
            score += 20
            reasons.append("Brute force login activity detected")
        elif failed_count >= 3:
            score += 15
            reasons.append(f"{failed_count} failed login attempts")

        if has_success and not has_brute_success:
            score += 10
            reasons.append("Successful authentication observed")

        if has_privesc:
            score += 25
            reasons.append("Privilege escalation detected")

        if has_powershell:
            score += 25
            reasons.append("Suspicious PowerShell execution")

        if has_persistence:
            score += 35
            reasons.append("Persistence mechanism detected")

        if has_lateral:
            score += 30
            reasons.append("Lateral movement detected")

        if has_cred_dump:
            score += 50
            reasons.append("Credential dumping detected")

        # Only create chains with meaningful correlation
        meaningful = (
            has_brute_success or
            has_persistence or
            has_cred_dump or
            has_privesc or
            ("brute_force" in packs or "authentication_failure" in packs) or
            (has_powershell and has_success) or
            has_lateral
        )

        if not meaningful:
            continue

        if score >= 80:
            severity = "CRITICAL"
            decision = "ESCALATE"
        elif score >= 50:
            severity = "HIGH"
            decision = "INVESTIGATE"
        elif score >= 30:
            severity = "MEDIUM"
            decision = "MONITOR"
        else:
            severity = "LOW"
            decision = "MONITOR"

        # Build kill chain label
        if len(kill_chain_phases) >= 3:
            chain_label = f"Multi-Stage Attack: {' → '.join(kill_chain_phases[:4])}"
        elif len(kill_chain_phases) == 2:
            chain_label = f"{kill_chain_phases[0]} → {kill_chain_phases[1]}"
        else:
            chain_label = kill_chain_phases[0] if kill_chain_phases else "Correlated Activity"

        chain = {
            "chain_id": f"CHAIN-{len(chains)+1:05d}",
            "chain_label": chain_label,
            "kill_chain_phases": kill_chain_phases,
            "host": host,
            "user": user,
            "severity": severity,
            "decision": decision,
            "risk_score": score,
            "confidence": "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW",
            "reasons": reasons,
            "mitre": sorted(set(m for a in group for m in a.get("mitre", []))),
            "alert_count": len(group),
            "timeline": [
                {
                    "time": a["time"],
                    "event_id": a["event_id"],
                    "kill_chain_phase": a.get("kill_chain_phase", "Unknown"),
                    "stage": a["pack"],
                    "event": a["title"],
                    "details": a["summary"],
                    "host": a["host"],
                    "user": a["user"],
                    "process": a["process"],
                    "mitre": a["mitre"]
                }
                for a in group
            ],
            "alerts": group,
            "recommended_actions": sorted(set(
                action
                for a in group
                for action in a.get("recommended_actions", [])
            ))
        }
        chains.append(chain)

    return chains

def build_investigations(alerts, chains):
    investigations = []
    chain_map = {}
    for chain in chains:
        for a in chain["alerts"]:
            chain_map[a["alert_id"]] = chain

    for alert in alerts:
        related_chain = chain_map.get(alert["alert_id"])

        investigations.append({
            "investigation_id": f"INV-{len(investigations)+1:05d}",
            "alert_id": alert["alert_id"],
            "time": alert["time"],
            "host": alert["host"],
            "user": alert["user"],
            "event_id": alert["event_id"],
            "rule_id": alert["rule_id"],
            "rule_description": alert["rule_description"],
            "process": alert["process"],
            "parent_process": alert["parent_process"],
            "command_line": alert["command_line"],
            "severity": alert["severity"],
            "kill_chain_phase": alert.get("kill_chain_phase", "Unknown"),
            "mitre": alert["mitre"],
            "fp_notes": alert.get("fp_notes", ""),
            "title": alert["title"],
            "summary": alert["summary"],
            "related_chain_id": related_chain["chain_id"] if related_chain else None,
            "chain_severity": related_chain["severity"] if related_chain else None,
            "chain_decision": related_chain["decision"] if related_chain else "MONITOR",
            "chain_reasons": related_chain["reasons"] if related_chain else [],
            "chain_kill_chain_phases": related_chain.get("kill_chain_phases", []) if related_chain else [],
            "confidence": compute_alert_confidence(alert["severity"], related_chain),
            "recommended_actions": alert["recommended_actions"],
            "validation": {
                "brute_force_preceded": any(
                    a["pack"] in ["brute_force", "brute_force_success"]
                    for a in (related_chain["alerts"] if related_chain else [])
                ),
                "privilege_escalation_observed": any(
                    a["pack"] == "privilege_escalation"
                    for a in (related_chain["alerts"] if related_chain else [])
                ),
                "powershell_observed": any(
                    a["pack"] == "malicious_powershell"
                    for a in (related_chain["alerts"] if related_chain else [])
                ),
                "persistence_observed": any(
                    a["pack"] == "persistence"
                    for a in (related_chain["alerts"] if related_chain else [])
                ),
                "lateral_movement_observed": any(
                    a["pack"] == "lateral_movement"
                    for a in (related_chain["alerts"] if related_chain else [])
                ),
            }
        })

    return investigations

def build_dashboard(alerts, chains):
    hosts = sorted(set(
        a["host"] for a in alerts
        if a["host"] not in ["unknown", "network"]
    ))

    return {
        "overview": {
            "total_devices": len(hosts),
            "critical_devices": len(set(c["host"] for c in chains if c["severity"] == "CRITICAL")),
            "high_devices": len(set(c["host"] for c in chains if c["severity"] == "HIGH")),
            "medium_devices": len(set(c["host"] for c in chains if c["severity"] == "MEDIUM")),
            "low_devices": len(set(c["host"] for c in chains if c["severity"] == "LOW")),
            "total_incidents": len(alerts),
            "total_attack_chains": len(chains),
            "critical_alerts": len([a for a in alerts if a["severity"] == "CRITICAL"]),
            "high_alerts": len([a for a in alerts if a["severity"] == "HIGH"]),
            "medium_alerts": len([a for a in alerts if a["severity"] == "MEDIUM"]),
            "multi_stage_attacks": len([c for c in chains if len(c.get("kill_chain_phases", [])) >= 3]),
        },
        "devices": [{"host": h} for h in hosts],
        "recent_incidents": alerts[:20],
        "recent_attack_chains": chains[:10],
        "priority_queue": {
            "escalate": [c for c in chains if c["decision"] == "ESCALATE"],
            "investigate": [c for c in chains if c["decision"] == "INVESTIGATE"],
            "monitor": [c for c in chains if c["decision"] == "MONITOR"],
        }
    }

def load_from_db():
    import sqlite3
    db_path = REPORTS_DIR / "clearsoc.db"
    if not db_path.exists():
        return []
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM events ORDER BY timestamp ASC")
        rows = c.fetchall()
        conn.close()
        events = []
        for row in rows:
            e = dict(row)
            try:
                import json as _json
                e["raw"] = _json.loads(e.get("raw_json") or "{}")
            except:
                e["raw"] = {}
            events.append(e)
        return events
    except Exception as ex:
        print(f"DB error: {ex}")
        return []


def save_alerts_to_db(alerts, chains):
    import sqlite3
    import json as _json
    from datetime import datetime
    db_path = REPORTS_DIR / "clearsoc.db"
    if not db_path.exists():
        return
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        now = datetime.now().isoformat()

        for a in alerts:
            c.execute("""
                INSERT OR REPLACE INTO soc_alerts
                (alert_id, timestamp, host, user, event_id, rule_id, pack,
                 rule_name, title, summary, severity, kill_chain_phase,
                 mitre, recommended_actions, fp_notes, status, inserted_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                a.get("alert_id",""), a.get("time",""), a.get("host",""),
                a.get("user",""), a.get("event_id",""), a.get("rule_id",""),
                a.get("pack",""), a.get("rule_name",""), a.get("title",""),
                a.get("summary",""), a.get("severity",""),
                a.get("kill_chain_phase",""),
                _json.dumps(a.get("mitre",[])),
                _json.dumps(a.get("recommended_actions",[])),
                a.get("fp_notes",""), a.get("status","OPEN"), now
            ))

        for ch in chains:
            c.execute("""
                INSERT OR REPLACE INTO attack_chains
                (chain_id, chain_label, host, user, severity, decision,
                 risk_score, confidence, kill_chain_phases, mitre,
                 reasons, timeline, inserted_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                ch.get("chain_id",""), ch.get("chain_label",""),
                ch.get("host",""), ch.get("user",""),
                ch.get("severity",""), ch.get("decision",""),
                ch.get("risk_score",0), ch.get("confidence",""),
                _json.dumps(ch.get("kill_chain_phases",[])),
                _json.dumps(ch.get("mitre",[])),
                _json.dumps(ch.get("reasons",[])),
                _json.dumps(ch.get("timeline",[])), now
            ))

        conn.commit()
        c.execute("INSERT INTO audit_log (action, details, timestamp) VALUES (?,?,?)",
                  ("PIPELINE", f"Saved {len(alerts)} alerts, {len(chains)} chains", now))
        conn.commit()
        conn.close()
        print(f"DB: Saved {len(alerts)} alerts and {len(chains)} chains")
    except Exception as ex:
        print(f"DB save error: {ex}")

def main():
    print("=== ClearSOC SOC Pipeline V2 ===")

    # Try DB first, fall back to JSON
    db_events = load_from_db()
    if db_events:
        print(f"Loaded {len(db_events)} events from database")
        raw_logs = db_events
    else:
        print("DB empty, falling back to raw_logs.json")
        raw_data = load_json(RAW_LOGS_FILE, [])
        raw_logs = flatten_logs(raw_data)

    events = [normalize_event(e) for e in raw_logs]

    alerts = build_alerts(events)
    chains = build_attack_chains(alerts)
    investigations = build_investigations(alerts, chains)
    dashboard = build_dashboard(alerts, chains)

    save_json(SOC_ALERTS_FILE, alerts)
    save_json(ATTACK_CHAINS_FILE, chains)
    save_json(INVESTIGATIONS_FILE, investigations)
    save_json(DASHBOARD_FILE, dashboard)
    save_alerts_to_db(alerts, chains)

    print(f"Raw logs:      {len(raw_logs)}")
    print(f"SOC alerts:    {len(alerts)}")
    print(f"Attack chains: {len(chains)}")
    print(f"Investigations:{len(investigations)}")

    if chains:
        print("\nChains generated:")
        for c in chains:
            print(f"  {c['chain_id']} | {c['chain_label']} | {c['severity']} | score:{c['risk_score']} | {c['host']}:{c['user']}")

if __name__ == "__main__":
    main()
