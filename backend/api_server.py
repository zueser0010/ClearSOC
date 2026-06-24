from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import json
import os

app = FastAPI(title="ClearSOC API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.abspath(os.path.join(BASE_DIR, "../reports"))

WAZUH_ALERTS = "/var/ossec/logs/alerts/alerts.json"
WAZUH_ARCHIVES = "/var/ossec/logs/archives/archives.json"
SURICATA_EVE = "/var/log/suricata/eve.json"

def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return json.load(f)
    except Exception:
        return default


def load_report(filename, default):
    return load_json(os.path.join(REPORTS_DIR, filename), default)


def read_json_lines(path, limit=200):
    logs = []

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()[-limit:]

        for line in lines:
            line = line.strip()
            if not line:
                continue

            try:
                logs.append(json.loads(line))
            except Exception:
                continue

        return {
            "total_logs": len(logs),
            "source": path,
            "logs": logs
        }

    except Exception as e:
        return {
            "total_logs": 0,
            "source": path,
            "logs": [],
            "error": str(e)
        }


@app.get("/")
def root():
    return {
        "name": "ClearSOC API",
        "status": "online"
    }


@app.get("/api/health")
def health():
    return {
        "status": "online",
        "reports_dir": REPORTS_DIR
    }


@app.get("/api/dashboard")
def dashboard():
    return load_report("dashboard_data.json", {})



@app.get("/api/alerts")
def get_alerts():
    return load_report("soc_alerts.json", [])


@app.get("/api/incidents")
def incidents():
    return load_report("investigations.json", [])



@app.get("/api/investigations")
def investigations():
    return load_report("investigations.json", [])
@app.get("/api/attack-chains")
def attack_chains():
    return load_report("attack_chains.json", [])


@app.get("/api/devices")
def devices():
    return load_report("device_summary.json", {})


@app.get("/api/priority-queue")
def priority_queue():
    return load_report("priority_queue.json", {})


@app.get("/api/iocs")
def iocs():
    return load_report("iocs.json", {})


@app.get("/api/raw-logs")
def raw_logs():
    return load_report("raw_logs.json", {
        "total_logs": 0,
        "logs": []
    })


@app.get("/api/threat-hunts")
def threat_hunts():
    return load_report("threat_hunts.json", {})


@app.get("/api/soar-actions")
def soar_actions():
    return load_report("soar_actions.json", {})


@app.get("/api/mttd")
def mttd():
    return load_report("mttd_metrics.json", {})


@app.get("/api/live-wazuh")
def live_wazuh(limit: int = 200, source: str = "alerts"):
    """
    Live Wazuh log reader.

    source=alerts   -> /var/ossec/logs/alerts/alerts.json
    source=archives -> /var/ossec/logs/archives/archives.json
    """

    if limit > 2000:
        limit = 2000

    if source == "archives":
        return read_json_lines(WAZUH_ARCHIVES, limit)

    return read_json_lines(WAZUH_ALERTS, limit)


@app.get("/api/live-alerts")
def live_alerts(limit: int = 200):
    return read_json_lines(WAZUH_ALERTS, limit)


@app.get("/api/live-archives")
def live_archives(limit: int = 200):
    return read_json_lines(WAZUH_ARCHIVES, limit)
@app.get("/api/live-suricata")
def live_suricata(limit: int = 200):
    if limit > 2000:
        limit = 2000

    return read_json_lines(SURICATA_EVE, limit)


@app.get("/api/live-zeek")
def live_zeek(log_type: str = "conn", limit: int = 200):
    return {
        "total_logs": 0,
        "source": f"zeek:{log_type}",
        "logs": [],
        "installed": False,
        "message": "Zeek is not installed yet"
    }


@app.get("/api/network-status")
def network_status():
    return {
        "wazuh_alerts": os.path.exists(WAZUH_ALERTS),
        "wazuh_archives": os.path.exists(WAZUH_ARCHIVES),
        "suricata": os.path.exists(SURICATA_EVE),
        "zeek": False
    }

@app.get("/api/events-by-date")
def events_by_date(date: str = None, start: str = None, end: str = None, limit: int = 500):
    import sqlite3
    db_path = os.path.join(BASE_DIR, "../reports/clearsoc.db")
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        if date:
            c.execute("""
                SELECT id, timestamp, host, user, event_id, rule_id,
                       rule_level, rule_description, source_ip, process,
                       parent_process, command_line, provider
                FROM events
                WHERE substr(timestamp,1,10) = ?
                ORDER BY timestamp ASC
                LIMIT ?
            """, (date, limit))
        elif start and end:
            c.execute("""
                SELECT id, timestamp, host, user, event_id, rule_id,
                       rule_level, rule_description, source_ip, process,
                       parent_process, command_line, provider
                FROM events
                WHERE substr(timestamp,1,10) >= ? AND substr(timestamp,1,10) <= ?
                ORDER BY timestamp ASC
                LIMIT ?
            """, (start, end, limit))
        else:
            c.execute("""
                SELECT id, timestamp, host, user, event_id, rule_id,
                       rule_level, rule_description, source_ip, process,
                       parent_process, command_line, provider
                FROM events
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows
    except Exception as e:
        return []

@app.get("/api/events-summary")
def events_summary():
    import sqlite3
    db_path = os.path.join(BASE_DIR, "../reports/clearsoc.db")
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("""
            SELECT substr(timestamp,1,10) as day, COUNT(*) as total,
                   SUM(CASE WHEN event_id != "" THEN 1 ELSE 0 END) as windows_events
            FROM events
            GROUP BY day
            ORDER BY day DESC
            LIMIT 60
        """)
        rows = [{"date": r[0], "total": r[1], "windows_events": r[2]} for r in c.fetchall()]
        conn.close()
        return rows
    except Exception as e:
        return []

@app.get("/api/host-alerts")
def host_alerts(host: str, exclude_id: str = ""):
    try:
        alerts = load_report("soc_alerts.json", [])
        if not isinstance(alerts, list):
            alerts = []
        filtered = [a for a in alerts if a.get("host","").lower() == host.lower() and a.get("alert_id","") != exclude_id]
        return filtered
    except:
        return []

@app.get("/api/zeek-context")
def zeek_context(host_ip: str = "", alert_time: str = "", window_minutes: int = 5):
    import os, datetime
    result = {"connections": [], "dns": [], "available": False}
    conn_log = "/opt/zeek/logs/current/conn.log"
    dns_log = "/opt/zeek/logs/current/dns.log"
    if not os.path.exists(conn_log):
        return result
    result["available"] = True
    try:
        alert_dt = datetime.datetime.fromisoformat(alert_time.replace("Z","+00:00")) if alert_time else None
    except:
        alert_dt = None
    def in_window(ts_str):
        if not alert_dt or not ts_str:
            return True
        try:
            ts = datetime.datetime.fromtimestamp(float(ts_str), tz=datetime.timezone.utc)
            diff = abs((ts - alert_dt.astimezone(datetime.timezone.utc)).total_seconds())
            return diff <= window_minutes * 60
        except:
            return True
    try:
        with open(conn_log) as f:
            headers = []
            for line in f:
                line = line.strip()
                if line.startswith("#fields"):
                    headers = line.split("\t")[1:]
                    continue
                if line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) < len(headers):
                    continue
                row = dict(zip(headers, parts))
                if host_ip and host_ip not in (row.get("id.orig_h",""), row.get("id.resp_h","")):
                    continue
                if not in_window(row.get("ts","")):
                    continue
                result["connections"].append({
                    "src": row.get("id.orig_h",""),
                    "dst": row.get("id.resp_h",""),
                    "dst_port": row.get("id.resp_p",""),
                    "proto": row.get("proto",""),
                    "service": row.get("service",""),
                    "duration": row.get("duration",""),
                    "bytes_sent": row.get("orig_bytes",""),
                    "bytes_recv": row.get("resp_bytes",""),
                    "conn_state": row.get("conn_state","")
                })
    except Exception as e:
        result["conn_error"] = str(e)
    try:
        with open(dns_log) as f:
            headers = []
            for line in f:
                line = line.strip()
                if line.startswith("#fields"):
                    headers = line.split("\t")[1:]
                    continue
                if line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) < len(headers):
                    continue
                row = dict(zip(headers, parts))
                if host_ip and row.get("id.orig_h","") != host_ip:
                    continue
                if not in_window(row.get("ts","")):
                    continue
                result["dns"].append({
                    "query": row.get("query",""),
                    "answer": row.get("answers",""),
                    "qtype": row.get("qtype_name","")
                })
    except Exception as e:
        result["dns_error"] = str(e)
    return result
