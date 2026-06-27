import json
from pathlib import Path
from fastapi import APIRouter, Request
import subprocess
import sys

router = APIRouter(prefix="/api/settings", tags=["settings"])

SETTINGS_FILE = Path("../reports/settings.json")

# Default settings
DEFAULT_SETTINGS = {
    "siem": {
        "type": "wazuh",
        "alerts_path": "/var/ossec/logs/alerts/alerts.json",
        "alerts_exists": Path("/var/ossec/logs/alerts/alerts.json").exists(),
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
    "pipeline": {
        "events_in_db": 0,
        "alerts_count": 0,
        "chains_count": 0,
        "investigations_count": 0
    },
    "custom_rules": []
}

def load_settings():
    if SETTINGS_FILE.exists():
        try:
            with open(SETTINGS_FILE) as f:
                data = json.load(f)
                # Merge with defaults to ensure all keys exist
                for key in DEFAULT_SETTINGS:
                    if key not in data:
                        data[key] = DEFAULT_SETTINGS[key]
                return data
        except:
            return DEFAULT_SETTINGS.copy()
    return DEFAULT_SETTINGS.copy()

def save_settings(data):
    SETTINGS_FILE.parent.mkdir(exist_ok=True)
    with open(SETTINGS_FILE, "w") as f:
        json.dump(data, f, indent=2)

@router.get("/")
async def get_settings():
    settings = load_settings()
    # Update pipeline stats
    try:
        from pathlib import Path
        alerts_file = Path("../reports/soc_alerts.json")
        if alerts_file.exists():
            with open(alerts_file) as f:
                alerts = json.load(f)
                if isinstance(alerts, list):
                    settings["pipeline"]["alerts_count"] = len(alerts)
        
        chains_file = Path("../reports/attack_chains.json")
        if chains_file.exists():
            with open(chains_file) as f:
                chains = json.load(f)
                if isinstance(chains, list):
                    settings["pipeline"]["chains_count"] = len(chains)
        
        inv_file = Path("../reports/investigations.json")
        if inv_file.exists():
            with open(inv_file) as f:
                inv = json.load(f)
                if isinstance(inv, list):
                    settings["pipeline"]["investigations_count"] = len(inv)
        
        raw_file = Path("../reports/raw_logs.json")
        if raw_file.exists():
            with open(raw_file) as f:
                raw = json.load(f)
                if isinstance(raw, dict) and "logs" in raw:
                    settings["pipeline"]["events_in_db"] = len(raw.get("logs", []))
                elif isinstance(raw, list):
                    settings["pipeline"]["events_in_db"] = len(raw)
    except:
        pass
    
    return settings

@router.post("/")
async def save_settings(request: Request):
    data = await request.json()
    save_settings(data)
    return {"status": "ok", "message": "Settings saved"}

@router.post("/run-pipeline")
async def run_pipeline():
    try:
        result = subprocess.run(
            ["python3", "soc_pipeline_v2.py"],
            cwd="/home/alwin/ClearSOC/backend",
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
