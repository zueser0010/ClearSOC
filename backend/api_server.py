from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import json
import os
import subprocess
import sys
from pathlib import Path

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
CONFIG_FILE = os.path.join(REPORTS_DIR, "settings.json")

WAZUH_ALERTS = "/var/ossec/logs/alerts/alerts.json"
WAZUH_ARCHIVES = "/var/ossec/logs/archives/archives.json"

# ========== HELPERS ==========

def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return json.load(f)
    except Exception:
        return default

def load_report(filename, default):
    return load_json(os.path.join(REPORTS_DIR, filename), default)

def load_config():
    default = {
        "siem": {
            "type": "wazuh",
            "alerts_path": WAZUH_ALERTS,
            "alerts_exists": Path(WAZUH_ALERTS).exists(),
            "archives_path": "/var/ossec/logs/archives/"
        },
        "escalation": {
            "email": "",
            "whatsapp": "",
            "sms": ""
        },
        "thresholds": {
            "brute_force_count": 5,
            "brute_force_window_minutes": 5,
            "min_rule_level": 3
        },
        "custom_rules": []
    }
    config = load_json(CONFIG_FILE, default)
    # Ensure all keys exist
    for key in default:
        if key not in config:
            config[key] = default[key]
    return config

def save_config(config):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)

# ========== SETTINGS ENDPOINTS ==========

@app.get("/api/settings")
async def get_settings():
    config = load_config()
    # Update live stats
    config["siem"]["alerts_exists"] = Path(WAZUH_ALERTS).exists()
    
    alerts = load_report("soc_alerts.json", [])
    chains = load_report("attack_chains.json", [])
    investigations = load_report("investigations.json", [])
    
    config["pipeline"] = {
        "events_in_db": len(load_report("raw_logs.json", {}).get("logs", [])),
        "alerts_count": len(alerts) if isinstance(alerts, list) else 0,
        "chains_count": len(chains) if isinstance(chains, list) else 0,
        "investigations_count": len(investigations) if isinstance(investigations, list) else 0
    }
    return config

@app.post("/api/settings")
async def save_settings(request: Request):
    data = await request.json()
    config = load_config()
    for key in data:
        if key in config:
            config[key] = data[key]
    save_config(config)
    return {"status": "ok", "message": "Settings saved"}

@app.post("/api/settings/run-pipeline")
async def run_pipeline():
    try:
        result = subprocess.run(
            [sys.executable, "soc_pipeline_v2.py"],
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            timeout=120
        )
        return {
            "status": "ok" if result.returncode == 0 else "error",
            "output": result.stdout + result.stderr
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Pipeline timed out after 120 seconds"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ========== ALERTS ==========

@app.get("/api/alerts")
async def get_alerts():
    data = load_report("soc_alerts.json", [])
    return data if isinstance(data, list) else []

@app.get("/api/incidents")
async def get_incidents():
    data = load_report("investigations.json", [])
    return data if isinstance(data, list) else []

@app.get("/api/attack-chains")
async def get_attack_chains():
    data = load_report("attack_chains.json", [])
    return data if isinstance(data, list) else []

@app.get("/api/dashboard")
async def get_dashboard():
    return load_report("dashboard_data.json", {})

@app.get("/api/raw-logs")
async def get_raw_logs():
    data = load_report("raw_logs.json", {})
    if isinstance(data, dict):
        return data.get("logs", [])
    return data if isinstance(data, list) else []

@app.get("/api/wazuh/alerts")
async def get_wazuh_alerts():
    return load_json(WAZUH_ALERTS, [])

@app.get("/api/wazuh/archives")
async def get_wazuh_archives():
    return load_json(WAZUH_ARCHIVES, [])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)

@app.get("/api/suricata-context")
def suricata_context(host_ip: str = "", alert_time: str = "", window_minutes: int = 10):
    import datetime, os
    result = {"alerts": [], "available": False}
    eve_log = "/var/log/suricata/eve.json"
    if not os.path.exists(eve_log):
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
            ts = datetime.datetime.fromisoformat(ts_str.replace("Z","+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=datetime.timezone.utc)
            adt = alert_dt.astimezone(datetime.timezone.utc)
            diff = abs((ts - adt).total_seconds())
            return diff <= window_minutes * 60
        except:
            return True
    try:
        import json as _j
        with open(eve_log) as f:
            for line in f:
                try:
                    ev = _j.loads(line.strip())
                    if ev.get("event_type") != "alert":
                        continue
                    if host_ip and ev.get("src_ip") != host_ip and ev.get("dest_ip") != host_ip:
                        continue
                    if not in_window(ev.get("timestamp","")):
                        continue
                    result["alerts"].append({
                        "signature": ev.get("alert",{}).get("signature","Unknown"),
                        "severity": ev.get("alert",{}).get("severity",3),
                        "category": ev.get("alert",{}).get("category",""),
                        "src_ip": ev.get("src_ip",""),
                        "dest_ip": ev.get("dest_ip",""),
                        "dest_port": ev.get("dest_port",""),
                        "timestamp": ev.get("timestamp",""),
                        "proto": ev.get("proto","")
                    })
                except:
                    continue
    except Exception as e:
        result["error"] = str(e)
    return result
