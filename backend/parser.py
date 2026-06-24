import json
import sqlite3
import os
from pathlib import Path
from datetime import datetime

ALERTS_FILE = Path("/var/ossec/logs/alerts/alerts.json")
CURRENT_MONTH = datetime.now().strftime("%B")
CURRENT_YEAR = datetime.now().year
HISTORICAL_ALERT_DIR = Path(f"/var/ossec/logs/alerts/{CURRENT_YEAR}/{CURRENT_MONTH}")
DB_PATH = Path("../reports/clearsoc.db")
RAW_LOGS_FILE = Path("../reports/raw_logs.json")

def get_nested(obj, path, default=""):
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(part)
    return cur if cur not in [None, ""] else default

def parse_alert(raw):
    event_id = (
        get_nested(raw, "data.win.system.eventID") or
        get_nested(raw, "data.win.system.eventId") or ""
    )
    user = (
        get_nested(raw, "data.win.eventdata.targetUserName") or
        get_nested(raw, "data.win.eventdata.subjectUserName") or
        get_nested(raw, "data.win.eventdata.user") or
        get_nested(raw, "data.dstuser") or
        get_nested(raw, "data.srcuser") or ""
    )
    if "\\" in str(user):
        user = str(user).split("\\")[-1]
    user = str(user).lower().strip()

    source_ip = (
        get_nested(raw, "data.win.eventdata.ipAddress") or
        get_nested(raw, "data.srcip") or
        get_nested(raw, "agent.ip") or ""
    )
    process = (
        get_nested(raw, "data.win.eventdata.image") or
        get_nested(raw, "data.win.eventdata.processName") or ""
    )
    parent_process = (
        get_nested(raw, "data.win.eventdata.parentImage") or ""
    )
    command_line = (
        get_nested(raw, "data.win.eventdata.commandLine") or ""
    )
    host = get_nested(raw, "agent.name") or "unknown"
    if "DESKTOP-G0LLA16" in str(host):
        host = "windows10"

    return {
        "id": raw.get("id", ""),
        "timestamp": raw.get("timestamp", ""),
        "host": host,
        "rule_id": get_nested(raw, "rule.id", ""),
        "rule_level": get_nested(raw, "rule.level", 0),
        "rule_description": get_nested(raw, "rule.description", ""),
        "event_id": str(event_id),
        "user": user,
        "source_ip": source_ip,
        "process": process,
        "parent_process": parent_process,
        "command_line": command_line,
        "provider": get_nested(raw, "data.win.system.providerName", "wazuh"),
        "raw": raw
    }

def save_to_db(events):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.utcnow().isoformat()
    inserted = 0
    for e in events:
        try:
            c.execute('''
                INSERT OR IGNORE INTO events
                (id, timestamp, host, user, event_id, rule_id, rule_level,
                 rule_description, source_ip, process, parent_process,
                 command_line, provider, raw_json, inserted_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ''', (
                e["id"], e["timestamp"], e["host"], e["user"],
                e["event_id"], e["rule_id"], e["rule_level"],
                e["rule_description"], e["source_ip"], e["process"],
                e["parent_process"], e["command_line"], e["provider"],
                json.dumps(e["raw"]), now
            ))
            if c.rowcount > 0:
                inserted += 1
        except Exception as ex:
            pass
    conn.commit()

    # Audit log
    c.execute('INSERT INTO audit_log (action, details, timestamp) VALUES (?,?,?)',
              ('PARSE', f'Inserted {inserted} new events', now))
    conn.commit()
    conn.close()
    return inserted

def load_from_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM events ORDER BY timestamp DESC')
    rows = c.fetchall()
    conn.close()
    events = []
    for row in rows:
        e = dict(row)
        try:
            e["raw"] = json.loads(e.get("raw_json", "{}"))
        except:
            e["raw"] = {}
        events.append(e)
    return events

def main():
    print("=== ClearSOC Parser (LIVE + DB) ===")

    raw_events = []

    if ALERTS_FILE.exists():
        print(f"Reading LIVE alerts from: {ALERTS_FILE}")
        with open(ALERTS_FILE, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    raw_events.append(parse_alert(raw))
                except:
                    pass
        print(f"Parsed {len(raw_events)} live alerts")

    # Save new events to DB
    inserted = save_to_db(raw_events)
    print(f"New events inserted to DB: {inserted}")

    # Load all events from DB for pipeline
    all_events = load_from_db()
    print(f"Total events in DB: {len(all_events)}")

    # Count Windows events
    win_events = [e for e in all_events if e.get("event_id")]
    from collections import Counter
    eids = Counter(e["event_id"] for e in win_events)
    print(f"Windows events: {len(win_events)}")
    print(f"Top Event IDs: {dict(eids.most_common(8))}")

    # Save to raw_logs.json for pipeline compatibility
    output = {"total_logs": len(all_events), "logs": all_events}
    with open(RAW_LOGS_FILE, 'w') as f:
        json.dump(output, f)
    print(f"Saved to: {RAW_LOGS_FILE}")

if __name__ == "__main__":
    main()
