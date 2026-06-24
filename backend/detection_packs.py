import json
import re
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

def safe_lower(value):
    if value is None:
        return ""
    return str(value).lower()

def get_event_id(event):
    return str(event.get("event_id", "") or "")

def get_process(event):
    return safe_lower(event.get("process", "") or "")

def get_parent_process(event):
    return safe_lower(event.get("parent_process", "") or "")

def get_command_line(event):
    return safe_lower(event.get("command_line", "") or "")

def get_user(event):
    user = event.get("user", "") or ""
    if "\\" in user:
        user = user.split("\\")[-1]
    return user.lower().strip()

def get_host(event):
    return event.get("host", "") or ""

# ── Whitelists ──────────────────────────────────────────
WHITELISTED_ACCOUNTS = {
    "system", "network service", "local service",
    "svc_backup", "svc_antivirus", "svc_monitoring",
    "nt authority", "window manager", "dwm-1", "dwm-2"
}

WHITELISTED_PARENTS = {
    "wazuh-agent.exe", "vmtoolsd.exe", "msiexec.exe",
    "services.exe", "svchost.exe", "taskhostw.exe"
}

EXPECTED_ADMIN_ACCOUNTS = {
    "administrator", "it_admin", "domain admin"
}

ALLOWED_PS_PARENTS = {
    "explorer.exe", "taskeng.exe", "schtasks.exe"
}

# ── Suppression ─────────────────────────────────────────
_suppression_cache = {}

def is_suppressed(key, window_seconds=60):
    now = datetime.utcnow()
    if key in _suppression_cache:
        if (now - _suppression_cache[key]).total_seconds() < window_seconds:
            return True
    _suppression_cache[key] = now
    return False

# ── State trackers ───────────────────────────────────────
_brute_force_tracker = defaultdict(list)
_login_success_tracker = defaultdict(list)
_lateral_movement_tracker = defaultdict(set)
_lateral_movement_times = defaultdict(list)

# =========================================================
# RULE 1: BRUTE FORCE + SUCCESS CORRELATION (T1110, T1078)
# Fires ONLY when failed logins are detected
# Upgrades to HIGH if followed by successful login
# =========================================================

def detect_brute_force(event):
    eid = get_event_id(event)
    user = get_user(event)
    host = get_host(event)

    if user in WHITELISTED_ACCOUNTS:
        return None

    now = event.get("parsed_time") or datetime.utcnow()
    window = timedelta(minutes=5)

    # Track successful logins per user/host
    if eid == "4624":
        key = f"{host}:{user}"
        _login_success_tracker[key].append(now)
        return None  # 4624 alone = no alert

    if eid != "4625":
        return None

    key = f"{host}:{user}"
    _brute_force_tracker[key].append(now)
    _brute_force_tracker[key] = [
        t for t in _brute_force_tracker[key]
        if (now - t) <= window
    ]

    count = len(_brute_force_tracker[key])

    if count < 3:
        return None

    if 3 <= count < 10:
        suppress_key = f"authfail:{key}"
        if is_suppressed(suppress_key, window_seconds=300):
            return None

        return {
            "matched": True,
            "pack": "authentication_failure",
            "rule_name": "Repeated Authentication Failures",
            "severity": "MEDIUM",
            "title": "Authentication Failure Spike",
            "summary": f"{count} failed logins in 5 min | User: {user} | Host: {host}",
            "mitre": ["T1110"],
            "kill_chain_phase": "Initial Access",
            "recommended_actions": [
                "Verify if the user mistyped password",
                "Check source IP and logon type",
                "Monitor for successful login after failures"
            ],
            "fp_notes": "3-9 failures may be user error. Do not call it brute force unless volume increases."
        }

    # Check if successful login followed the failures
    recent_success = [
        t for t in _login_success_tracker.get(key, [])
        if (now - t) <= window
    ]

    suppress_key = f"bruteforce:{key}"
    if is_suppressed(suppress_key, window_seconds=300):
        return None

    if recent_success:
        return {
            "matched": True,
            "pack": "brute_force_success",
            "rule_name": "Brute Force + Successful Login",
            "severity": "CRITICAL",
            "title": "🔨 Brute Force Followed by Successful Login",
            "summary": f"{count} failed logins then successful login | User: {user} | Host: {host}",
            "mitre": ["T1110", "T1078"],
            "kill_chain_phase": "Initial Access",
            "fp_notes": "High confidence TP — failed logins followed by success is account compromise pattern",
            "recommended_actions": [
                "Disable account immediately pending investigation",
                "Check source IP — internal vs external",
                "Review what was accessed after successful login",
                "Check for 4672 (privilege escalation) after this event"
            ]
        }
    else:
        return {
            "matched": True,
            "pack": "brute_force",
            "rule_name": "Brute Force Detected",
            "severity": "MEDIUM",
            "title": "🔨 Brute Force Login Attempt",
            "summary": f"{count} failed logins in 5 min | User: {user} | Host: {host}",
            "mitre": ["T1110"],
            "kill_chain_phase": "Initial Access",
            "fp_notes": "Could be password expiry or account lockout — no confirmed success yet",
            "recommended_actions": [
                "Check if account is now locked",
                "Verify source IP",
                "Monitor for successful login (4624) following this"
            ]
        }

# =========================================================
# RULE 2: PRIVILEGE ESCALATION (T1078.002)
# Event ID 4672 — fires only for non-admin users
# Upgraded to CRITICAL if brute force preceded it
# =========================================================

def detect_privilege_escalation(event):
    if get_event_id(event) != "4672":
        return None

    user = get_user(event)
    host = get_host(event)

    if user in WHITELISTED_ACCOUNTS:
        return None
    if user in EXPECTED_ADMIN_ACCOUNTS:
        return None

    suppress_key = f"privesc:{host}:{user}"
    if is_suppressed(suppress_key, window_seconds=300):
        return None

    # Check if brute force preceded this
    bf_key = f"{host}:{user}"
    recent_bf = len(_brute_force_tracker.get(bf_key, [])) >= 5

    severity = "CRITICAL" if recent_bf else "HIGH"
    title = "👑 Privilege Escalation After Brute Force" if recent_bf else "👑 Unexpected Admin Privileges"

    return {
        "matched": True,
        "pack": "privilege_escalation",
        "rule_name": "Privilege Escalation",
        "severity": severity,
        "title": title,
        "summary": f"User '{user}' received special privileges on {host}" + (" (preceded by brute force)" if recent_bf else ""),
        "mitre": ["T1078.002"],
        "kill_chain_phase": "Privilege Escalation",
        "fp_notes": "Verify if scheduled IT maintenance — check change management",
        "recommended_actions": [
            "Verify if user normally has admin rights",
            "Check what was executed after privilege assignment",
            "Correlate with brute force or lateral movement alerts",
            "Review Event ID 4720/4732 for account creation"
        ]
    }

# =========================================================
# RULE 3: ACCOUNT CREATION / ADMIN GROUP CHANGE (T1136)
# Event ID 4720 = new user, 4732 = added to admin group
# Near-zero FP — always escalate
# =========================================================

def detect_persistence_account(event):
    eid = get_event_id(event)

    if eid not in ["4720", "4732"]:
        return None

    user = get_user(event)
    host = get_host(event)

    if user in WHITELISTED_ACCOUNTS:
        return None

    suppress_key = f"account:{eid}:{host}:{user}"
    if is_suppressed(suppress_key, window_seconds=300):
        return None

    if eid == "4720":
        return {
            "matched": True,
            "pack": "persistence",
            "rule_name": "New User Account Created",
            "severity": "CRITICAL",
            "title": "🆕 New User Account Created",
            "summary": f"New account created on {host} — possible persistence mechanism",
            "mitre": ["T1136.001"],
            "kill_chain_phase": "Persistence",
            "fp_notes": "Near-zero FP — verify with IT if account creation was planned",
            "recommended_actions": [
                "Identify who created the account",
                "Check if account was added to admin groups (4732)",
                "Disable account immediately if unplanned",
                "Escalate to L2"
            ]
        }

    if eid == "4732":
        return {
            "matched": True,
            "pack": "persistence",
            "rule_name": "User Added to Admin Group",
            "severity": "CRITICAL",
            "title": "👥 User Added to Administrators Group",
            "summary": f"Account added to privileged group on {host} — persistence or privilege abuse",
            "mitre": ["T1098"],
            "kill_chain_phase": "Persistence",
            "fp_notes": "Near-zero FP — escalate unless change was planned",
            "recommended_actions": [
                "Remove account from admin group immediately if unplanned",
                "Identify who made the change",
                "Check for lateral movement from this host",
                "Escalate to L2"
            ]
        }

# =========================================================
# RULE 4: MALICIOUS POWERSHELL (T1059.001)
# Only fires on suspicious PowerShell — not all PS
# =========================================================

def detect_malicious_powershell(event):
    eid = get_event_id(event)

    if eid not in ["1", "4688"]:
        return None

    process = get_process(event)
    if "powershell" not in process and "pwsh" not in process:
        return None

    parent = get_parent_process(event)
    user = get_user(event)

    # Suppress known-good system PowerShell
    if user in WHITELISTED_ACCOUNTS:
        return None

    # Suppress known-good parents
    if any(p in parent for p in WHITELISTED_PARENTS):
        return None

    command = get_command_line(event)
    score = 0
    reasons = []

    if "-enc" in command or "-encodedcommand" in command:
        score += 40
        reasons.append("Encoded command (-enc)")

    if "iex" in command or "invoke-expression" in command:
        score += 30
        reasons.append("Dynamic execution (IEX)")

    if "downloadstring" in command or "downloadfile" in command:
        score += 35
        reasons.append("Network download")

    if "bypass" in command:
        score += 20
        reasons.append("Execution policy bypass")

    if "hidden" in command or "-w hidden" in command:
        score += 15
        reasons.append("Hidden window")

    if "mimikatz" in command or "sekurlsa" in command:
        score += 100
        reasons.append("Credential dumping tool")

    if any(p in parent for p in ["winword", "excel", "outlook", "powerpnt"]):
        score += 50
        reasons.append("Spawned from Office application")

    if any(p in parent for p in ["wscript", "cscript", "mshta"]):
        score += 40
        reasons.append("Script engine parent")

    if score < 30:
        return None

    severity = "CRITICAL" if score >= 80 else "HIGH" if score >= 50 else "MEDIUM"

    suppress_key = f"powershell:{get_host(event)}:{user}:{score}"
    if is_suppressed(suppress_key, window_seconds=60):
        return None

    return {
        "matched": True,
        "pack": "malicious_powershell",
        "rule_name": "Malicious PowerShell",
        "severity": severity,
        "title": f"⚡ Suspicious PowerShell Execution (score:{score})",
        "summary": " | ".join(reasons),
        "mitre": ["T1059.001"],
        "kill_chain_phase": "Execution",
        "fp_notes": "Verify command — check if admin script or scheduled task",
        "recommended_actions": [
            "Decode base64 command if encoded",
            "Check parent process context",
            "Look for file drops or network connections after execution",
            "Correlate with login events on same host"
        ]
    }

# =========================================================
# RULE 5: LATERAL MOVEMENT (T1021)
# Fires when same user authenticates to 2+ hosts
# =========================================================

def detect_lateral_movement(event):
    if get_event_id(event) not in ["4624", "4648"]:
        return None

    user = get_user(event)
    host = get_host(event)
    now = event.get("parsed_time") or datetime.utcnow()

    if user in WHITELISTED_ACCOUNTS:
        return None

    _lateral_movement_tracker[user].add(host)
    _lateral_movement_times[user].append(now)

    window = timedelta(minutes=10)
    _lateral_movement_times[user] = [
        t for t in _lateral_movement_times[user]
        if (now - t) <= window
    ]

    unique_hosts = len(_lateral_movement_tracker[user])

    if unique_hosts >= 2:
        suppress_key = f"lateral:{user}"
        if is_suppressed(suppress_key, window_seconds=300):
            return None
        return {
            "matched": True,
            "pack": "lateral_movement",
            "rule_name": "Lateral Movement",
            "severity": "HIGH",
            "title": "🔄 Lateral Movement Detected",
            "summary": f"User '{user}' authenticated to {unique_hosts} hosts: {list(_lateral_movement_tracker[user])}",
            "mitre": ["T1021"],
            "kill_chain_phase": "Lateral Movement",
            "fp_notes": "Could be IT admin — verify if user has legitimate reason to access multiple hosts",
            "recommended_actions": [
                "Map all hosts accessed by this user",
                "Check what was executed on each host",
                "Correlate with brute force or credential dumping alerts",
                "Isolate if confirmed malicious"
            ]
        }

    return None

# =========================================================
# RULE 6: CREDENTIAL DUMPING (T1003)
# Near-zero FP
# =========================================================

def detect_credential_dumping(event):
    command = get_command_line(event)
    process = get_process(event)
    user = get_user(event)

    if user in WHITELISTED_ACCOUNTS:
        return None

    dump_patterns = [
        r"lsass", r"sekurlsa", r"mimikatz",
        r"procdump.*lsass", r"task.*lsass",
        r"reg.*save.*sam", r"reg.*export.*sam",
        r"\\system32\\config\\sam",
        r"vssadmin.*delete", r"ntds\.dit"
    ]

    for pattern in dump_patterns:
        if re.search(pattern, command) or re.search(pattern, process):
            suppress_key = f"creddump:{get_host(event)}"
            if is_suppressed(suppress_key, window_seconds=300):
                return None
            return {
                "matched": True,
                "pack": "credential_dumping",
                "rule_name": "Credential Dumping",
                "severity": "CRITICAL",
                "title": "💀 Credential Dumping Detected",
                "summary": f"Pattern: {pattern} | Process: {process}",
                "mitre": ["T1003"],
                "kill_chain_phase": "Credential Access",
                "fp_notes": "Near-zero FP — treat as confirmed unless pentest scheduled",
                "recommended_actions": [
                    "Isolate host immediately",
                    "Reset all credentials on this host",
                    "Check for data exfiltration",
                    "Preserve memory dump for forensics",
                    "Escalate to L2/L3 immediately"
                ]
            }

    return None

# =========================================================
# DETECTION ENGINE
# =========================================================


# =========================================================
# RULE: EXECUTABLE DROPPED IN SUSPICIOUS LOCATION (T1105)
# Sysmon Event ID 11 - File Created
# Rule IDs: 92213, 92217, 92205
# =========================================================

def detect_executable_dropped(event):
    if get_event_id(event) not in ["11"]:
        return None

    rule_id = str(event.get("rule_id", ""))
    rule_desc = (event.get("rule_description") or "").lower()
    user = get_user(event)
    host = get_host(event)

    suspicious_rules = ["92213", "92217", "92205", "92200", "92201"]
    suspicious_keywords = [
        "executable", "dropped", "malware", "windows root",
        "scripting file", "temp", "powershell"
    ]

    if rule_id not in suspicious_rules:
        if not any(k in rule_desc for k in suspicious_keywords):
            return None

    if user in WHITELISTED_ACCOUNTS:
        return None

    suppress_key = f"exe_drop:{host}:{rule_id}"
    if is_suppressed(suppress_key, window_seconds=120):
        return None

    severity = "HIGH" if rule_id in ["92213", "92217", "92205"] else "MEDIUM"

    return {
        "matched": True,
        "pack": "malware_drop",
        "rule_name": "Executable Dropped in Suspicious Location",
        "severity": severity,
        "title": "🦠 Suspicious Executable Dropped",
        "summary": f"Executable file created in suspicious location | Host: {host} | Rule: {event.get('rule_description','')}",
        "mitre": ["T1105"],
        "kill_chain_phase": "Persistence",
        "fp_notes": "Check if software installation was planned — verify with change management",
        "recommended_actions": [
            "Identify the process that dropped the file",
            "Check file hash against VirusTotal",
            "Verify if software installation was authorized",
            "Check for follow-up execution of the dropped file"
        ]
    }


# =========================================================
# RULE: SUSPICIOUS CMD/PROCESS EXECUTION (T1059.003)
# Sysmon Event ID 1 - Process Creation
# Rule IDs: 92032, 92052, 92031, 92066
# =========================================================

def detect_suspicious_execution(event):
    if get_event_id(event) not in ["1", "4688"]:
        return None

    rule_id = str(event.get("rule_id", ""))
    rule_desc = (event.get("rule_description") or "").lower()
    user = get_user(event)
    host = get_host(event)

    suspicious_rules = ["92032", "92052", "92031", "92066"]
    suspicious_keywords = [
        "suspicious", "abnormal", "discovery", "cmd shell",
        "command prompt started by", "secedit", "suspicious location"
    ]

    if rule_id not in suspicious_rules:
        if not any(k in rule_desc for k in suspicious_keywords):
            return None

    if user in WHITELISTED_ACCOUNTS:
        return None

    parent = get_parent_process(event)
    if any(p in parent for p in WHITELISTED_PARENTS):
        return None

    suppress_key = f"susp_exec:{host}:{rule_id}"
    if is_suppressed(suppress_key, window_seconds=120):
        return None

    # Determine kill chain phase
    if "discovery" in rule_desc:
        phase = "Discovery"
        mitre = ["T1082", "T1087"]
        title = "🔍 Discovery Activity Detected"
    else:
        phase = "Execution"
        mitre = ["T1059.003"]
        title = "⚡ Suspicious Process Execution"

    return {
        "matched": True,
        "pack": "suspicious_execution",
        "rule_name": "Suspicious Process Execution",
        "severity": "MEDIUM",
        "title": title,
        "summary": f"{event.get('rule_description','')} | Host: {host} | Process: {get_process(event)}",
        "mitre": mitre,
        "kill_chain_phase": phase,
        "fp_notes": "Verify parent process — could be legitimate admin activity",
        "recommended_actions": [
            "Check parent process context",
            "Verify if activity was authorized",
            "Correlate with login events on same host",
            "Check for file drops or network connections after execution"
        ]
    }


# =========================================================
# RULE: PASS THE HASH / ANONYMOUS LOGON (T1550.002)
# Event ID 4624 - NTLM Anonymous Logon
# Rule ID: 92652
# =========================================================

def detect_pass_the_hash(event):
    if get_event_id(event) not in ["4624"]:
        return None

    rule_id = str(event.get("rule_id", ""))
    rule_desc = (event.get("rule_description") or "").lower()

    if rule_id != "92652":
        if "pass-the-hash" not in rule_desc and "anonymous logon" not in rule_desc:
            return None

    user = get_user(event)
    host = get_host(event)

    suppress_key = f"pth:{host}"
    if is_suppressed(suppress_key, window_seconds=300):
        return None

    return {
        "matched": True,
        "pack": "pass_the_hash",
        "rule_name": "Pass-the-Hash Attack",
        "severity": "CRITICAL",
        "title": "💀 Pass-the-Hash Attack Detected",
        "summary": f"NTLM anonymous logon detected — possible credential relay attack | Host: {host}",
        "mitre": ["T1550.002"],
        "kill_chain_phase": "Lateral Movement",
        "fp_notes": "Near-zero FP — NTLM anonymous logon is highly suspicious",
        "recommended_actions": [
            "Isolate host immediately",
            "Check for lateral movement from this host",
            "Reset credentials for all accounts on this host",
            "Escalate to L2/L3 immediately",
            "Check for Mimikatz or credential dumping tools"
        ]
    }


# =========================================================
# RULE: AUDIT POLICY CHANGED (T1562.002)
# Event ID 4719
# Rule ID: 60112
# =========================================================

def detect_audit_policy_change(event):
    if get_event_id(event) != "4719":
        return None

    user = get_user(event)
    host = get_host(event)

    if user in WHITELISTED_ACCOUNTS:
        return None

    suppress_key = f"audit_policy:{host}"
    if is_suppressed(suppress_key, window_seconds=600):
        return None

    return {
        "matched": True,
        "pack": "defense_evasion",
        "rule_name": "Audit Policy Changed",
        "severity": "HIGH",
        "title": "🛡️ Audit Policy Modified",
        "summary": f"Windows audit policy changed on {host} — attacker may be disabling logging",
        "mitre": ["T1562.002"],
        "kill_chain_phase": "Defense Evasion",
        "fp_notes": "Could be legitimate IT policy change — verify with change management",
        "recommended_actions": [
            "Verify if audit policy change was authorized",
            "Check what specific policies were changed",
            "Re-enable audit logging if disabled",
            "Investigate who made the change and why"
        ]
    }


# =========================================================
# RULE: SERVICE STARTUP TYPE CHANGED (T1543.003)
# Event ID 7040
# Rule ID: 61104
# =========================================================

def detect_service_change(event):
    if get_event_id(event) != "7040":
        return None

    rule_id = str(event.get("rule_id", ""))
    user = get_user(event)
    host = get_host(event)

    if user in WHITELISTED_ACCOUNTS:
        return None

    suppress_key = f"svc_change:{host}"
    if is_suppressed(suppress_key, window_seconds=300):
        return None

    return {
        "matched": True,
        "pack": "persistence",
        "rule_name": "Service Startup Type Changed",
        "severity": "MEDIUM",
        "title": "⚙️ Service Configuration Modified",
        "summary": f"Service startup type changed on {host} — possible persistence mechanism",
        "mitre": ["T1543.003"],
        "kill_chain_phase": "Persistence",
        "fp_notes": "Could be legitimate software installation — check change management",
        "recommended_actions": [
            "Identify which service was modified",
            "Verify if change was authorized",
            "Check service binary path for malicious executables",
            "Correlate with other suspicious activity on same host"
        ]
    }


DETECTION_FUNCTIONS = [
    detect_brute_force,
    detect_privilege_escalation,
    detect_persistence_account,
    detect_malicious_powershell,
    detect_lateral_movement,
    detect_credential_dumping,
    detect_executable_dropped,
    detect_suspicious_execution,
    detect_pass_the_hash,
    detect_audit_policy_change,
    detect_service_change,
]

def run_detection_packs(event):
    if not isinstance(event, dict):
        return []
    findings = []
    for detector in DETECTION_FUNCTIONS:
        try:
            result = detector(event)
            if result:
                findings.append(result)
        except Exception:
            pass
    return findings

__all__ = ['run_detection_packs']

def detect_generic_security_event(event):
    """Generate alert for any Windows security event - for testing"""
    event_id = event.get('event_id', '')
    
    # List of interesting Windows event IDs
    interesting_events = ['4624', '4625', '4672', '4688', '4698', '4702', '4720', '4732', '4738', '4768', '4776']
    
    if event_id in interesting_events:
        host = event.get('host', 'unknown')
        user = event.get('user', 'unknown')
        
        # Map event ID to description
        descriptions = {
            '4624': 'Successful Logon',
            '4625': 'Failed Logon', 
            '4672': 'Admin Privileges Assigned',
            '4688': 'Process Creation',
            '4720': 'User Account Created',
            '4732': 'User Added to Admin Group'
        }
        
        return {
            'matched': True,
            'pack': 'generic_security',
            'rule_name': f'Windows Security Event {event_id}',
            'severity': 'MEDIUM',
            'title': f'🛡️ {descriptions.get(event_id, "Security Event")}',
            'summary': f'Event {event_id} on {host} by {user}',
            'mitre': ['T1078'],
            'kill_chain_phase': 'Initial Access',
            'recommended_actions': ['Review this security event', 'Correlate with other events']
        }
    return None
