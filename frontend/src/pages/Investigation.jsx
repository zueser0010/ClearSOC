import { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";

const API = "http://localhost:8001";

const SEV_COLOR = { CRITICAL:"#ef4444", HIGH:"#f97316", MEDIUM:"#eab308", LOW:"#22c55e", INFO:"#3b82f6" };

function getRawEventData(alert) {
  return alert?.raw?.data?.win?.eventdata || alert?.raw?.raw?.data?.win?.eventdata || {};
}

function getRawSystemData(alert) {
  return alert?.raw?.data?.win?.system || alert?.raw?.raw?.data?.win?.system || {};
}

function generateAnalysis(alert, inv) {
  const eventId = String(alert?.event_id || "");
  const user = alert?.user || "Unknown";
  const host = alert?.host || "Unknown";
  const sourceIp = alert?.source_ip || getRawEventData(alert).ipAddress || "Unknown";
  const raw = getRawEventData(alert);
  const sys = getRawSystemData(alert);
  const title = alert?.rule_description || alert?.title || "Security alert detected";

  const baseMissing = [
    "No successful compromise is confirmed by this alert alone",
    "No full attack path is proven without supporting events",
    "Analyst must validate nearby logs before final conclusion"
  ];

  if (eventId === "4625") {
    const logonType = raw.logonType || "Unknown";
    const workstation = raw.workstationName || "Unknown";
    const status = raw.status || "Unknown";
    const subStatus = raw.subStatus || "Unknown";
    const authPackage = raw.authenticationPackageName || "Unknown";

    return {
      title: "Authentication Failure Explanation",
      trigger: "Windows Event ID 4625 was generated because an account failed to authenticate.",
      happened: [
        `Failed login detected for user: ${user}`,
        `Target host: ${host}`,
        `Source IP: ${sourceIp}`,
        `Workstation: ${workstation}`,
        `Logon Type: ${logonType}`,
        `Authentication Package: ${authPackage}`
      ],
      found: [
        "Event ID 4625 confirms a failed authentication attempt",
        `Failure status: ${status}`,
        `Sub status: ${subStatus}`,
        sourceIp !== "Unknown" ? `Remote source identified: ${sourceIp}` : "Source IP was not available"
      ],
      missing: [
        "No successful login event 4624 is confirmed by this alert alone",
        "No privilege escalation is confirmed by this alert alone",
        "No account creation or persistence is confirmed by this alert alone",
        "No lateral movement is confirmed by this alert alone"
      ],
      why: "Repeated authentication failures can indicate brute force, password spraying, expired credentials, mistyped passwords, or service account issues.",
      assessment: "This alert confirms authentication failure activity. It does not prove compromise by itself. If failures are low volume, treat as MONITOR. If failures increase or are followed by a successful login, escalate to INVESTIGATE.",
      confidence: inv?.confidence || "LOW",
      verdict: alert?.pack === "brute_force" ? "INVESTIGATE" : "MONITOR"
    };
  }

  if (eventId === "4624") {
    const logonType = raw.logonType || "Unknown";
    const workstation = raw.workstationName || "Unknown";
    const authPackage = raw.authenticationPackageName || "Unknown";

    return {
      title: "Successful Login Explanation",
      trigger: "Windows Event ID 4624 was generated because an account successfully authenticated.",
      happened: [
        `Successful login by user: ${user}`,
        `Target host: ${host}`,
        `Source IP: ${sourceIp}`,
        `Workstation: ${workstation}`,
        `Logon Type: ${logonType}`,
        `Authentication Package: ${authPackage}`
      ],
      found: [
        "Event ID 4624 confirms successful authentication",
        "Account access was granted",
        sourceIp !== "Unknown" ? `Login source identified: ${sourceIp}` : "Source IP was not available"
      ],
      missing: [
        "No malicious process execution is confirmed by this alert alone",
        "No privilege escalation is confirmed by this alert alone",
        "No persistence is confirmed by this alert alone"
      ],
      why: "Successful logins are normal, but become suspicious after repeated failures, from unusual IPs, unusual times, or unexpected logon types.",
      assessment: "This event confirms access was granted. Determine whether the login was expected. If it occurred after multiple failed logins or from an unusual source, investigate further.",
      confidence: inv?.confidence || "MEDIUM",
      verdict: "INVESTIGATE"
    };
  }

  if (eventId === "4672") {
    return {
      title: "Privileged Logon Explanation",
      trigger: "Windows Event ID 4672 was generated because special privileges were assigned to a logged-on account.",
      happened: [
        `Privileged logon detected for user: ${user}`,
        `Host: ${host}`,
        "Special privileges were assigned during logon",
        "This commonly happens when an administrator logs in"
      ],
      found: [
        "Event ID 4672 confirms privileged access was granted",
        "The account received elevated rights on the host"
      ],
      missing: [
        "No malicious command execution is confirmed by this alert alone",
        "No new account creation is confirmed by this alert alone",
        "No lateral movement is confirmed by this alert alone"
      ],
      why: "Privileged accounts are high-value targets. Unexpected privileged logons may indicate account misuse or compromise.",
      assessment: "This alert confirms elevated privileges. If the user is expected to be an administrator and timing/source are normal, it may be benign. If unexpected, investigate immediately.",
      confidence: inv?.confidence || "LOW",
      verdict: "INVESTIGATE"
    };
  }

  if (eventId === "4719") {
    const category = raw.category || "Unknown";
    const subcategory = raw.subcategory || "Unknown";
    const changes = raw.auditPolicyChanges || "Unknown";

    return {
      title: "Audit Policy Change Explanation",
      trigger: "Windows Event ID 4719 was generated because audit policy settings were changed.",
      happened: [
        `Audit policy modified by user: ${user}`,
        `Host: ${host}`,
        `Category: ${category}`,
        `Subcategory: ${subcategory}`,
        `Changes: ${changes}`
      ],
      found: [
        "Event ID 4719 confirms audit policy modification",
        "Security logging configuration was changed",
        changes !== "Unknown" ? `Observed change: ${changes}` : "Specific change details were not available"
      ],
      missing: [
        "No evidence confirms audit logging was disabled",
        "No PowerShell execution is confirmed by this alert alone",
        "No malware execution is confirmed by this alert alone",
        "No privilege escalation is confirmed by this alert alone"
      ],
      why: "Attackers may modify audit policy to reduce visibility, but administrators and Group Policy can also legitimately change auditing.",
      assessment: "This alert confirms audit policy changed. The current evidence does not prove malicious intent. If auditing was added, risk is lower. Verify change management, GPO activity, and administrator activity.",
      confidence: inv?.confidence || "LOW",
      verdict: "MONITOR"
    };
  }

  if (eventId === "4720") {
    const newUser = raw.targetUserName || alert?.user || "Unknown";

    return {
      title: "New User Account Explanation",
      trigger: "Windows Event ID 4720 was generated because a new local/domain user account was created.",
      happened: [
        `New account created: ${newUser}`,
        `Creator/related user: ${user}`,
        `Host: ${host}`
      ],
      found: [
        "Event ID 4720 confirms account creation",
        "A new identity now exists in the environment"
      ],
      missing: [
        "No admin group membership is confirmed by this alert alone",
        "No malicious login using the new account is confirmed by this alert alone",
        "No persistence usage is confirmed by this alert alone"
      ],
      why: "Attackers often create backdoor accounts after gaining access. Admins also create accounts during normal operations.",
      assessment: "This alert should be investigated. Confirm whether the account creation was authorized and whether the account was added to privileged groups.",
      confidence: inv?.confidence || "MEDIUM",
      verdict: "INVESTIGATE"
    };
  }

  if (eventId === "4732") {
    const member = raw.memberName || raw.targetUserName || "Unknown";
    const group = raw.targetUserName || raw.groupName || "Administrators";

    return {
      title: "Admin Group Membership Explanation",
      trigger: "Windows Event ID 4732 was generated because a user was added to a security-enabled local group.",
      happened: [
        `Account/member added: ${member}`,
        `Group affected: ${group}`,
        `Host: ${host}`,
        `Actor: ${user}`
      ],
      found: [
        "Event ID 4732 confirms group membership modification",
        "Potential privilege increase occurred"
      ],
      missing: [
        "No proof the added account was used maliciously",
        "No command execution is confirmed by this alert alone",
        "No lateral movement is confirmed by this alert alone"
      ],
      why: "Adding accounts to privileged groups is a common persistence and privilege escalation technique.",
      assessment: "This is high-value evidence. Verify whether the membership change was approved. If unexpected, escalate.",
      confidence: inv?.confidence || "MEDIUM",
      verdict: "INVESTIGATE"
    };
  }

  if (eventId === "4688" || String(alert?.title || "").toLowerCase().includes("powershell") || String(alert?.command_line || "").toLowerCase().includes("powershell")) {
    const process = alert?.process || "Unknown";
    const parent = alert?.parent_process || "Unknown";
    const cmd = alert?.command_line || "No command line available";

    return {
      title: "Process Execution / PowerShell Explanation",
      trigger: "Process execution was detected and matched suspicious execution logic.",
      happened: [
        `Process: ${process}`,
        `Parent process: ${parent}`,
        `User: ${user}`,
        `Host: ${host}`,
        `Command line: ${cmd}`
      ],
      found: [
        "Process execution activity was observed",
        cmd.toLowerCase().includes("-enc") || cmd.toLowerCase().includes("encodedcommand") ? "Encoded PowerShell command detected" : "Command line was captured",
        cmd.toLowerCase().includes("bypass") ? "Execution policy bypass detected" : "No execution policy bypass observed in command line"
      ],
      missing: [
        "Decoded payload must be reviewed before final conclusion",
        "No confirmed malware execution from this alert alone",
        "No confirmed data exfiltration from this alert alone"
      ],
      why: "PowerShell and command interpreters are commonly used by attackers, but also used by administrators. Encoded commands and bypass flags increase suspicion.",
      assessment: "This alert requires investigation. Decode any encoded payload, review parent process, and check surrounding events for download, persistence, credential access, or network connections.",
      confidence: inv?.confidence || "MEDIUM",
      verdict: "INVESTIGATE"
    };
  }

  return {
    title: "General Alert Explanation",
    trigger: title,
    happened: [
      title,
      `User involved: ${user}`,
      `Affected host: ${host}`,
      `Event ID: ${eventId || "Unknown"}`
    ],
    found: [
      "Security-relevant activity was detected",
      "Wazuh/ClearSOC generated an alert"
    ],
    missing: baseMissing,
    why: "This event may be suspicious depending on surrounding context, user behavior, host role, time, source, and related activity.",
    assessment: "This alert requires analyst validation. Do not conclude compromise from this alert alone. Review related logons, process execution, privilege changes, persistence, lateral movement, and IOCs.",
    confidence: inv?.confidence || "LOW",
    verdict: "INVESTIGATE"
  };
}

function decodePowerShellEncodedCommand(commandLine = "") {
  const match = commandLine.match(/-(enc|encodedcommand|e)\s+([A-Za-z0-9+/=]+)/i);
  if (!match) return null;

  try {
    const base64 = match[2];
    const binary = atob(base64);

    // PowerShell -EncodedCommand usually uses UTF-16LE
    let decoded = "";
    for (let i = 0; i < binary.length; i += 2) {
      decoded += String.fromCharCode(binary.charCodeAt(i) | (binary.charCodeAt(i + 1) << 8));
    }

    return decoded.trim();
  } catch (e) {
    return "Failed to decode Base64 PowerShell command.";
  }
}

export default function Investigation() {
  const navigate = useNavigate();
  const [alert, setAlert] = useState(null);
  const [inv, setInv] = useState(null);
  const [loading, setLoading] = useState(true);
  const [verdict, setVerdict] = useState(null);
  const [showEscalate, setShowEscalate] = useState(false);
  const [escalateMsg, setEscalateMsg] = useState("");
  const [sent, setSent] = useState(false);
  const [showDecoded, setShowDecoded] = useState(false);
  const [notes, setNotes] = useState(localStorage.getItem("clearsoc_investigation_notes") || "");
  const [hostAlerts, setHostAlerts] = useState([]);
  const [zeekData, setZeekData] = useState(null);
  const [rawFields, setRawFields] = useState({});

  useEffect(() => {
    const selected = JSON.parse(localStorage.getItem("clearsoc_selected_alert") || "null");
    if (!selected) { setLoading(false); return; }
    setAlert(selected);
    const msg = `[ClearSOC ALERT]
Severity: ${selected.severity}
Host: ${selected.host}
User: ${selected.user}
Event: ${selected.title}
Time: ${selected.time}
Kill Chain: ${selected.kill_chain_phase || "Unknown"}
MITRE: ${(selected.mitre||[]).join(", ")}
Summary: ${selected.summary}
Action Required: Immediate investigation`;
    setEscalateMsg(msg);
    fetch(`${API}/api/investigations`)
      .then(r => r.json())
      .then(data => {
        const found = (Array.isArray(data) ? data : []).find(i => i.alert_id === selected.alert_id);
        setInv(found || null);
      })
      .catch(() => setInv(null))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div style={{padding:"40px",color:"#94a3b8"}}>Loading investigation...</div>;

  if (!alert) return (
    <div style={{padding:"40px",textAlign:"center"}}>
      <h2 style={{color:"white"}}>No Alert Selected</h2>
      <p style={{color:"#64748b"}}>Go to Alerts and click Investigate on an alert.</p>
      <button onClick={() => navigate("/alerts")} style={{marginTop:"16px",background:"rgba(56,189,248,0.1)",border:"1px solid rgba(56,189,248,0.3)",color:"#38bdf8",padding:"10px 20px",borderRadius:"8px",cursor:"pointer"}}>← Back to Alerts</button>
    </div>
  );

  const caseId = "CASE-" + new Date().getFullYear() + "-" + String(
    Math.abs((alert.alert_id || "1").split("").reduce((a,c)=>a+c.charCodeAt(0),0))
  ).padStart(5,"0");

  const sev = alert.severity || "LOW";
  const sevColor = SEV_COLOR[sev] || "#94a3b8";
  const validation = inv?.validation || {};
  const phases = inv?.chain_kill_chain_phases || [];
  const reasons = inv?.chain_reasons || [];
  const actions = alert.recommended_actions || [];

  const evidenceFound = Object.values(validation).filter(Boolean).length;
  const totalEvidence = Object.keys(validation).length || 1;
  const riskScore = Math.round((evidenceFound / totalEvidence) * 100);
  const analystAnalysis = generateAnalysis(alert, inv);

  // Confidence and verdict are driven by the alert's own severity, not the
  // per-event-ID narrative branch above. Chain data (inv.confidence) wins
  // when present since the backend now computes it correctly.
  function suggestVerdict(severity, confidence) {
    if (severity === "CRITICAL") return "ESCALATE";
    if (severity === "HIGH" && confidence === "HIGH") return "ESCALATE";
    if (severity === "HIGH" || severity === "MEDIUM") return "INVESTIGATE";
    return "MONITOR";
  }
  analystAnalysis.confidence = inv?.confidence || analystAnalysis.confidence || "LOW";
  analystAnalysis.verdict = suggestVerdict(sev, analystAnalysis.confidence);
  const decodedPowerShell = decodePowerShellEncodedCommand(alert.command_line || alert.raw?.command_line || "");

  const ALL_PHASES = ["Initial Access","Execution","Persistence","Privilege Escalation","Defense Evasion","Credential Access","Discovery","Lateral Movement","Collection","Exfiltration"];

  function handleVerdict(v) {
    setVerdict(v);
    if (v === "ESCALATE") setShowEscalate(true);
  }

  return (
    <div style={{padding:"20px",color:"#e2e8f0",maxWidth:"1600px"}}>
      <div style={{display:"grid",gridTemplateColumns:"1fr 380px",gap:"20px",alignItems:"flex-start"}}>
      <div>

      {/* ESCALATE MODAL */}
      {showEscalate && (
        <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.8)",zIndex:1000,display:"flex",alignItems:"center",justifyContent:"center"}}>
          <div style={{background:"#0f172a",border:"1px solid #ef4444",borderRadius:"16px",padding:"32px",width:"560px",maxWidth:"90vw"}}>
            <h2 style={{color:"#ef4444",margin:"0 0 8px"}}>🚨 Escalate to L2/L3</h2>
            <p style={{color:"#94a3b8",fontSize:"13px",margin:"0 0 20px"}}>Select escalation method and send alert details to your team.</p>

            <div style={{background:"rgba(239,68,68,0.05)",border:"1px solid rgba(239,68,68,0.2)",borderRadius:"8px",padding:"14px",marginBottom:"20px"}}>
              <p style={{color:"#64748b",fontSize:"11px",margin:"0 0 8px",textTransform:"uppercase",letterSpacing:"0.5px"}}>Alert Message</p>
              <textarea
                value={escalateMsg}
                onChange={e => setEscalateMsg(e.target.value)}
                style={{width:"100%",background:"transparent",border:"none",color:"#e2e8f0",fontSize:"12px",fontFamily:"monospace",resize:"vertical",minHeight:"120px",outline:"none"}}
              />
            </div>

            <p style={{color:"#64748b",fontSize:"12px",margin:"0 0 12px"}}>Send via:</p>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:"10px",marginBottom:"20px"}}>
              {[
                { label:"📧 Email", color:"#38bdf8", href:`mailto:soc-team@company.com?subject=ClearSOC ESCALATION: ${sev} Alert&body=${encodeURIComponent(escalateMsg)}` },
                { label:"💬 WhatsApp", color:"#22c55e", href:`https://wa.me/?text=${encodeURIComponent(escalateMsg)}` },
                { label:"📱 SMS", color:"#a855f7", href:`sms:?body=${encodeURIComponent(escalateMsg)}` },
              ].map(b => (
                <a key={b.label} href={b.href} target="_blank" rel="noreferrer"
                  onClick={() => setSent(true)}
                  style={{display:"flex",alignItems:"center",justifyContent:"center",gap:"8px",background:`${b.color}18`,border:`1px solid ${b.color}44`,color:b.color,padding:"12px",borderRadius:"8px",textDecoration:"none",fontSize:"13px",fontWeight:600}}>
                  {b.label}
                </a>
              ))}
            </div>

            {sent && <p style={{color:"#22c55e",fontSize:"13px",margin:"0 0 16px"}}>✓ Escalation initiated. Document this in your incident log.</p>}

            <div style={{display:"flex",gap:"10px",justifyContent:"flex-end"}}>
              <button onClick={() => { setShowEscalate(false); setSent(false); }}
                style={{background:"rgba(255,255,255,0.06)",border:"1px solid rgba(255,255,255,0.1)",color:"#94a3b8",padding:"10px 20px",borderRadius:"8px",cursor:"pointer"}}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* HEADER */}
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:"20px"}}>
        <div>
          <h1 style={{fontSize:"24px",fontWeight:700,color:"white",margin:0}}>🔍 Investigation Workspace</h1>
          <p style={{color:"#64748b",fontSize:"13px",margin:"4px 0 0"}}>Professional SOC Triage — {alert.title}</p>
          <p style={{color:"#38bdf8",fontSize:"12px",margin:"6px 0 0",fontWeight:700}}>{caseId}</p>
        </div>
        <div style={{display:"flex",gap:"10px",alignItems:"center"}}>
          <span style={{background:`${sevColor}22`,border:`1px solid ${sevColor}`,color:sevColor,padding:"6px 14px",borderRadius:"6px",fontWeight:700,fontSize:"13px",letterSpacing:"1px"}}>{sev}</span>
          <button onClick={() => navigate("/alerts")} style={{background:"rgba(255,255,255,0.06)",border:"1px solid rgba(255,255,255,0.1)",color:"#94a3b8",padding:"8px 14px",borderRadius:"8px",cursor:"pointer",fontSize:"13px"}}>← Back</button>
        </div>
      </div>

      {/* STEP 1 — VALIDATE & SCOPE */}
      <StepCard step="1" title="Validate & Scope" subtitle="Is this alert real? What is the context?" color="#38bdf8">
        <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:"12px",marginBottom:"16px"}}>
          <InfoBox label="Host" value={alert.host} icon="🖥️"/>
          <InfoBox label="User" value={alert.user} icon="👤"/>
          <InfoBox label="Source IP" value={alert.source_ip || "N/A"} icon="🌐"/>
          <InfoBox label="Event ID" value={alert.event_id || "N/A"} icon="🔖"/>
          <InfoBox label="Time (SGT)" value={alert.time?.replace("T"," ")?.split("+")[0]} icon="🕐"/>
          <InfoBox label="Kill Chain Phase" value={alert.kill_chain_phase || "Unknown"} icon="⛓️"/>
        </div>

        {/* Business Hours Check */}
        <div style={{background:"rgba(255,255,255,0.03)",border:"1px solid rgba(255,255,255,0.07)",borderRadius:"8px",padding:"14px",marginBottom:"12px"}}>
          <p style={{color:"#94a3b8",fontSize:"12px",margin:"0 0 8px",fontWeight:600}}>🕐 Business Hours Analysis (Singapore SGT)</p>
          {(() => {
            const t = new Date(alert.time);
            const hour = t.getHours();
            const isBusinessHours = hour >= 9 && hour <= 18;
            const isWeekend = t.getDay() === 0 || t.getDay() === 6;
            return (
              <div style={{display:"flex",gap:"16px",flexWrap:"wrap"}}>
                <Tag color={isBusinessHours ? "#22c55e" : "#ef4444"} label={isBusinessHours ? "Business Hours (9AM-6PM SGT)" : "⚠️ Outside Business Hours — RED FLAG"}/>
                <Tag color={isWeekend ? "#ef4444" : "#22c55e"} label={isWeekend ? "⚠️ Weekend Activity — RED FLAG" : "Weekday"}/>
                <Tag color={alert.source_ip === "127.0.0.1" ? "#eab308" : "#38bdf8"} label={alert.source_ip === "127.0.0.1" ? "Local Login (127.0.0.1)" : `External IP: ${alert.source_ip}`}/>
              </div>
            );
          })()}
        </div>

        {/* IP Reputation Links */}
        <div style={{background:"rgba(255,255,255,0.03)",border:"1px solid rgba(255,255,255,0.07)",borderRadius:"8px",padding:"14px"}}>
          <p style={{color:"#94a3b8",fontSize:"12px",margin:"0 0 10px",fontWeight:600}}>🔎 IP Reputation Check</p>
          <div style={{display:"flex",gap:"10px",flexWrap:"wrap"}}>
            {[
              { label:"VirusTotal", url:`https://www.virustotal.com/gui/ip-address/${alert.source_ip}`, color:"#3b82f6" },
              { label:"AbuseIPDB", url:`https://www.abuseipdb.com/check/${alert.source_ip}`, color:"#ef4444" },
              { label:"Shodan", url:`https://www.shodan.io/host/${alert.source_ip}`, color:"#f97316" },
            ].map(l => (
              <a key={l.label} href={l.url} target="_blank" rel="noreferrer"
                style={{background:`${l.color}18`,border:`1px solid ${l.color}44`,color:l.color,padding:"6px 14px",borderRadius:"6px",textDecoration:"none",fontSize:"12px",fontWeight:600}}>
                {l.label} →
              </a>
            ))}
          </div>
          {alert.source_ip === "127.0.0.1" && (
            <p style={{color:"#eab308",fontSize:"12px",margin:"10px 0 0"}}>ℹ️ Source IP is localhost (127.0.0.1) — this is a local login attempt, not external. Lower priority unless combined with other indicators.</p>
          )}
        </div>
      </StepCard>

      {/* POWERSHELL DECODER */}
      {decodedPowerShell && (
        <div style={{background:"rgba(8,18,38,0.95)",border:"1px solid rgba(56,189,248,0.18)",borderRadius:"12px",padding:"16px",marginBottom:"12px"}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"10px"}}>
            <div>
              <h3 style={{color:"#38bdf8",fontSize:"15px",margin:"0 0 4px"}}>🧬 Encoded PowerShell Decoder</h3>
              <p style={{color:"#64748b",fontSize:"12px",margin:0}}>Detected Base64 PowerShell encoded command in command line.</p>
            </div>
            <button
              onClick={() => setShowDecoded(!showDecoded)}
              style={{background:"rgba(56,189,248,0.12)",border:"1px solid rgba(56,189,248,0.35)",color:"#38bdf8",padding:"8px 14px",borderRadius:"8px",cursor:"pointer",fontWeight:700}}
            >
              {showDecoded ? "Hide Decoded" : "Decode Command"}
            </button>
          </div>

          {showDecoded && (
            <pre style={{background:"#020617",border:"1px solid rgba(56,189,248,0.2)",borderRadius:"8px",padding:"14px",fontSize:"12px",color:"#e2e8f0",overflow:"auto",whiteSpace:"pre-wrap",wordBreak:"break-word",maxHeight:"260px"}}>
              {decodedPowerShell}
            </pre>
          )}
        </div>
      )}

      {/* STEP 2 — DETECT PERSISTENCE */}
      <StepCard step="2" title="Detect Persistence & Lateral Movement" subtitle="Has the attacker tried to stay or spread?" color="#f97316">

        {/* Kill Chain Visualization */}
        {phases.length > 0 && (
          <div style={{marginBottom:"16px"}}>
            <p style={{color:"#94a3b8",fontSize:"12px",margin:"0 0 10px",fontWeight:600}}>⛓️ Kill Chain Progression</p>
            <div style={{display:"flex",flexWrap:"wrap",gap:"6px"}}>
              {ALL_PHASES.map((phase, i) => {
                const active = phases.includes(phase);
                const current = phase === alert.kill_chain_phase;
                return (
                  <div key={i} style={{padding:"5px 12px",borderRadius:"6px",fontSize:"11px",fontWeight:600,
                    background: current ? "rgba(249,115,22,0.2)" : active ? "rgba(56,189,248,0.15)" : "rgba(255,255,255,0.03)",
                    border: current ? "1px solid #f97316" : active ? "1px solid #38bdf8" : "1px solid rgba(255,255,255,0.06)",
                    color: current ? "#f97316" : active ? "#38bdf8" : "#334155"
                  }}>
                    {current ? "▶ " : active ? "✓ " : ""}{phase}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Evidence Checklist */}
        <p style={{color:"#94a3b8",fontSize:"12px",margin:"0 0 10px",fontWeight:600}}>📋 Evidence Checklist (Key Windows Event IDs)</p>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:"8px",marginBottom:"16px"}}>
          {[
            { label:"Authentication Failures (4625)", key:"brute_force_preceded", desc:"Failed login activity observed", eventId:"4625", match:["4625"] },
            { label:"Successful Login (4624)", key:"successful_login_observed", desc:"Account successfully authenticated", eventId:"4624", match:["4624"] },
            { label:"Privilege Escalation (4672)", key:"privilege_escalation_observed", desc:"Special privileges assigned to account", eventId:"4672", match:["4672"] },
            { label:"New Account Created (4720)", key:"persistence_observed", desc:"Account created on endpoint", eventId:"4720", match:["4720"] },
            { label:"Added to Admin Group (4732)", key:"persistence_observed", desc:"Account added to Administrators group", eventId:"4732", match:["4732"] },
            { label:"PowerShell Execution", key:"powershell_observed", desc:"Suspicious script execution detected", eventId:"4688/1", match:["4688","1"] },
            { label:"Lateral Movement (4624/4648)", key:"lateral_movement_observed", desc:"Authentication to multiple hosts detected", eventId:"4624/4648", match:["4648"] },
            { label:"Correlated Attack Chain", key:null, desc:"Multiple alerts linked to one attack", eventId:"—", match:[] },
          ].map((e, i) => {
            const currentEventId = String(alert.event_id || "");
            const currentRule = String(alert.rule_name || alert.pack || alert.title || "").toLowerCase();
            const directEventMatch = Array.isArray(e.match) && e.match.includes(currentEventId);
            const directPowerShellMatch = e.label.includes("PowerShell") && currentRule.includes("powershell");
            const found = directEventMatch || directPowerShellMatch || (e.key ? validation[e.key] : !!inv?.related_chain_id);
            return (
              <div key={i} style={{background: found ? "rgba(34,197,94,0.08)" : "rgba(255,255,255,0.03)", border: `1px solid ${found ? "rgba(34,197,94,0.25)" : "rgba(255,255,255,0.06)"}`, borderRadius:"8px", padding:"10px 14px"}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"4px"}}>
                  <strong style={{fontSize:"12px",color: found ? "#e2e8f0" : "#475569"}}>{e.label}</strong>
                  <span style={{fontSize:"10px",fontWeight:700,padding:"2px 8px",borderRadius:"4px",background: found ? "rgba(34,197,94,0.15)" : "rgba(148,163,184,0.08)", color: found ? "#22c55e" : "#64748b"}}>
                    {found ? "OBSERVED" : "NOT OBSERVED"}
                  </span>
                </div>
                <p style={{fontSize:"11px",color:"#64748b",margin:"0 0 4px"}}>{e.desc}</p>
                <span style={{fontSize:"10px",color:"#334155",fontFamily:"monospace"}}>Event ID: {e.eventId}</span>
              </div>
            );
          })}
        </div>

        {/* Correlation Reasons */}
        {reasons.length > 0 && (
          <div style={{background:"rgba(56,189,248,0.05)",border:"1px solid rgba(56,189,248,0.15)",borderRadius:"8px",padding:"14px"}}>
            <p style={{color:"#38bdf8",fontSize:"12px",margin:"0 0 10px",fontWeight:600}}>🔗 Correlation Evidence</p>
            {reasons.map((r, i) => (
              <div key={i} style={{display:"flex",alignItems:"flex-start",gap:"8px",marginBottom:"6px"}}>
                <span style={{color:"#22c55e",fontSize:"14px",marginTop:"1px"}}>✓</span>
                <span style={{fontSize:"12px",color:"#94a3b8"}}>{r}</span>
              </div>
            ))}
          </div>
        )}

        {/* FP Notes */}
        {alert.fp_notes && (
          <div style={{background:"rgba(234,179,8,0.05)",border:"1px solid rgba(234,179,8,0.2)",borderRadius:"8px",padding:"14px",marginTop:"12px"}}>
            <p style={{color:"#eab308",fontSize:"12px",margin:"0 0 6px",fontWeight:600}}>⚠️ False Positive Assessment</p>
            <p style={{fontSize:"12px",color:"#94a3b8",margin:0}}>{alert.fp_notes}</p>
          </div>
        )}
      </StepCard>


      {/* ANALYST FINDINGS */}
      <StepCard step="3" title="Analyst Findings" subtitle="Facts, missing evidence, assessment, and recommended verdict" color="#38bdf8">
        <div style={{background:"rgba(56,189,248,0.05)",border:"1px solid rgba(56,189,248,0.15)",borderRadius:"10px",padding:"14px",marginBottom:"14px"}}>
          <p style={{color:"#38bdf8",fontSize:"13px",fontWeight:700,margin:"0 0 8px"}}>🔎 {analystAnalysis.title}</p>
          <p style={{color:"#cbd5e1",fontSize:"13px",lineHeight:"1.6",margin:0}}>{analystAnalysis.assessment}</p>
        </div>

        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:"12px",marginBottom:"14px"}}>
          <FindingBox title="What Happened" icon="📌" items={analystAnalysis.happened} color="#38bdf8" />
          <FindingBox title="Evidence Found" icon="✅" items={analystAnalysis.found} color="#22c55e" />
          <FindingBox title="Evidence Missing" icon="⚪" items={analystAnalysis.missing} color="#94a3b8" />
        </div>

        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:"12px"}}>
          <MetricBox label="Analyst Confidence" value={analystAnalysis.confidence} color={analystAnalysis.confidence === "HIGH" ? "#22c55e" : analystAnalysis.confidence === "MEDIUM" ? "#eab308" : "#64748b"} />
          <MetricBox label="Suggested Verdict" value={analystAnalysis.verdict} color={analystAnalysis.verdict === "ESCALATE" ? "#ef4444" : analystAnalysis.verdict === "INVESTIGATE" ? "#f97316" : "#eab308"} />
        </div>
      </StepCard>

      {/* STEP 3 — ANALYST VERDICT */}
      <StepCard step="3" title="Analyst Verdict & Response" subtitle="Make a decision and take action" color="#a855f7">

        {/* Summary for non-technical */}
        <div style={{background:"rgba(168,85,247,0.05)",border:"1px solid rgba(168,85,247,0.2)",borderRadius:"8px",padding:"16px",marginBottom:"16px"}}>
          <p style={{color:"#a855f7",fontSize:"12px",margin:"0 0 8px",fontWeight:600}}>📊 Plain English Summary</p>
          <p style={{fontSize:"13px",color:"#cbd5e1",margin:0,lineHeight:"1.6"}}>
            {sev === "CRITICAL" ? "🔴 This is a confirmed critical threat. Immediate action required — isolate the host and escalate now." :
             sev === "HIGH" && (inv?.confidence === "HIGH" || evidenceFound >= 2) ? "🟠 High-confidence threat detected. Multiple evidence points support malicious activity. Investigate immediately and prepare to escalate." :
             sev === "HIGH" ? "🟠 High-severity event detected, but confidence is low. Validate user context, source IP, and related activity before escalating." :
             sev === "MEDIUM" ? "🟡 Suspicious activity detected. Could be malicious or a false positive. Investigate further before escalating." :
             "🟢 Low severity event. Likely benign but monitor for patterns. No immediate action required."}
          </p>
        </div>

        {/* Confidence Metrics */}
        <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:"10px",marginBottom:"16px"}}>
          <MetricBox label="Alert Severity" value={sev} color={sevColor}/>
          <MetricBox label="Evidence Found" value={`${evidenceFound}/${totalEvidence}`} color="#38bdf8"/>
          <MetricBox label="Chain Severity" value={inv?.chain_severity || "N/A"} color={SEV_COLOR[inv?.chain_severity] || "#94a3b8"}/>
          <MetricBox label="Confidence" value={inv?.confidence || "LOW"} color={inv?.confidence === "HIGH" ? "#22c55e" : inv?.confidence === "MEDIUM" ? "#eab308" : "#64748b"}/>
        </div>

        {/* Evidence Score */}
        <div style={{background:"rgba(255,255,255,0.03)",border:"1px solid rgba(255,255,255,0.07)",borderRadius:"10px",padding:"14px",marginBottom:"16px"}}>
          <div style={{display:"flex",justifyContent:"space-between",marginBottom:"8px"}}>
            <span style={{fontSize:"12px",color:"#94a3b8"}}>Evidence Score</span>
            <span style={{fontSize:"12px",color:"#38bdf8",fontWeight:700}}>{riskScore}%</span>
          </div>
          <div style={{height:"10px",background:"#0f172a",borderRadius:"999px",overflow:"hidden"}}>
            <div style={{width:`${riskScore}%`,height:"100%",background:riskScore >= 80 ? "#ef4444" : riskScore >= 50 ? "#f97316" : "#22c55e"}} />
          </div>
        </div>

        {/* Recommended Actions */}
        {actions.length > 0 && (
          <div style={{marginBottom:"16px"}}>
            <p style={{color:"#94a3b8",fontSize:"12px",margin:"0 0 10px",fontWeight:600}}>🛠️ Recommended Actions</p>
            <div style={{display:"flex",flexDirection:"column",gap:"6px"}}>
              {actions.map((a, i) => (
                <div key={i} style={{display:"flex",alignItems:"flex-start",gap:"10px",background:"rgba(255,255,255,0.03)",border:"1px solid rgba(255,255,255,0.06)",borderRadius:"6px",padding:"10px 14px"}}>
                  <span style={{color:"#38bdf8",fontWeight:700,fontSize:"13px",minWidth:"20px"}}>{i+1}.</span>
                  <span style={{fontSize:"12px",color:"#94a3b8"}}>{a}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* VERDICT BUTTONS */}
        {!verdict ? (
          <div>
            <p style={{color:"#94a3b8",fontSize:"12px",margin:"0 0 12px",fontWeight:600}}>🎯 Your Verdict</p>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:"12px"}}>
              <VerdictBtn
                label="✅ False Positive"
                sub="This alert is benign — no action needed"
                color="#22c55e"
                onClick={() => handleVerdict("FP")}
              />
              <VerdictBtn
                label="👁️ Monitor"
                sub="Keep watching — not enough evidence yet"
                color="#eab308"
                onClick={() => handleVerdict("MONITOR")}
              />
              <VerdictBtn
                label="🚨 Escalate to L2"
                sub="Confirmed threat — immediate response"
                color="#ef4444"
                onClick={() => handleVerdict("ESCALATE")}
              />
            </div>
          </div>
        ) : (
          <div style={{background: verdict==="FP"?"rgba(34,197,94,0.08)":verdict==="ESCALATE"?"rgba(239,68,68,0.08)":"rgba(234,179,8,0.08)", border:`1px solid ${verdict==="FP"?"#22c55e":verdict==="ESCALATE"?"#ef4444":"#eab308"}44`, borderRadius:"10px", padding:"16px"}}>
            <p style={{color:verdict==="FP"?"#22c55e":verdict==="ESCALATE"?"#ef4444":"#eab308",fontWeight:700,fontSize:"14px",margin:"0 0 6px"}}>
              {verdict==="FP"?"✅ Marked as False Positive":verdict==="ESCALATE"?"🚨 Escalated to L2/L3":"👁️ Set to Monitor"}
            </p>
            <p style={{color:"#64748b",fontSize:"12px",margin:"0 0 12px"}}>
              {verdict==="FP"?"Document why this is a FP and close the alert.":verdict==="ESCALATE"?"Escalation initiated. Notify your team immediately.":"Continue monitoring. Set a review time."}
            </p>
            <button onClick={() => { setVerdict(null); setSent(false); }} style={{background:"rgba(255,255,255,0.06)",border:"1px solid rgba(255,255,255,0.1)",color:"#94a3b8",padding:"8px 14px",borderRadius:"6px",cursor:"pointer",fontSize:"12px",marginRight:"8px"}}>
              Change Verdict
            </button>
            {verdict==="ESCALATE" && (
              <button onClick={() => setShowEscalate(true)} style={{background:"rgba(239,68,68,0.15)",border:"1px solid rgba(239,68,68,0.3)",color:"#ef4444",padding:"8px 14px",borderRadius:"6px",cursor:"pointer",fontSize:"12px"}}>
                📤 Send Notification
              </button>
            )}
          </div>
        )}
      </StepCard>


      {/* INVESTIGATION TIMELINE */}
      <div style={{background:"rgba(8,18,38,0.95)",border:"1px solid rgba(56,189,248,0.1)",borderRadius:"10px",padding:"16px",marginTop:"12px"}}>
        <p style={{color:"#38bdf8",fontSize:"13px",margin:"0 0 12px",fontWeight:700,textTransform:"uppercase"}}>⏱ Investigation Timeline</p>
        <div style={{display:"grid",gap:"8px"}}>
          {[
            { icon:"🚨", label:"Alert Generated", value:alert.time || "N/A" },
            { icon:"🔍", label:"Investigation Opened", value:new Date().toLocaleString() },
            { icon:"📋", label:"Evidence Reviewed", value:`${evidenceFound}/${totalEvidence} evidence points found` },
            { icon:"🎯", label:"Analyst Verdict", value:verdict || "Pending" },
          ].map((e,i)=>(
            <div key={i} style={{display:"grid",gridTemplateColumns:"36px 180px 1fr",gap:"10px",alignItems:"center",background:"rgba(255,255,255,0.03)",border:"1px solid rgba(255,255,255,0.06)",borderRadius:"8px",padding:"10px 12px"}}>
              <span>{e.icon}</span>
              <strong style={{fontSize:"12px",color:"#e2e8f0"}}>{e.label}</strong>
              <span style={{fontSize:"12px",color:"#94a3b8"}}>{e.value}</span>
            </div>
          ))}
        </div>
      </div>

      {/* ANALYST NOTES */}
      <div style={{background:"rgba(8,18,38,0.95)",border:"1px solid rgba(56,189,248,0.1)",borderRadius:"10px",padding:"16px",marginTop:"12px"}}>
        <p style={{color:"#38bdf8",fontSize:"13px",margin:"0 0 12px",fontWeight:700,textTransform:"uppercase"}}>📝 Analyst Notes</p>
        <textarea
          value={notes}
          onChange={(e)=>{
            setNotes(e.target.value);
            localStorage.setItem("clearsoc_investigation_notes", e.target.value);
          }}
          placeholder="Document investigation findings, assumptions, evidence, false positive reason, or escalation notes..."
          style={{width:"100%",minHeight:"140px",background:"#020617",color:"#e2e8f0",border:"1px solid rgba(56,189,248,0.2)",borderRadius:"8px",padding:"12px",fontSize:"13px",outline:"none",resize:"vertical"}}
        />
      </div>

      {/* RAW DATA */}
      <div style={{background:"rgba(8,18,38,0.95)",border:"1px solid rgba(56,189,248,0.1)",borderRadius:"10px",padding:"16px",marginTop:"12px"}}>
        <p style={{color:"#475569",fontSize:"11px",margin:"0 0 10px",fontWeight:600,textTransform:"uppercase"}}>📄 Raw Alert Data</p>
        <pre style={{background:"rgba(0,0,0,0.3)",border:"1px solid rgba(255,255,255,0.06)",borderRadius:"8px",padding:"14px",fontSize:"11px",color:"#475569",overflow:"auto",maxHeight:"300px",fontFamily:"monospace",whiteSpace:"pre-wrap",wordBreak:"break-all",margin:0}}>
          {JSON.stringify(alert.raw || alert, null, 2)}
        </pre>
      </div>

    </div>

      {/* RIGHT PANEL — EVIDENCE CONSOLE */}
      <div style={{position:"sticky",top:"20px",display:"flex",flexDirection:"column",gap:"12px"}}>

        {/* RAW EVENT DETAIL */}
        <RawEventDetail alert={alert} />
        {/* SAME HOST{/* SAME HOST ALERTS */}
        <HostAlertsPanel alert={alert} API={API} />

        {/* ZEEK NETWORK CONTEXT */}
        <ZeekPanel alert={alert} API={API} />

        {/* FP/TP ASSESSMENT */}
        <FpTpAssessmentWrapper alert={alert} inv={inv} API={API} />

      </div>
      </div>
    </div>
  );
}


function RawEventDetail({ alert }) {
  // Always try raw_json first as it has the full Windows event structure
  let raw = null;
  if (typeof alert?.raw_json === "string" && alert.raw_json.length > 10) {
    try { raw = JSON.parse(alert.raw_json); } catch(e) {}
  }
  if (!raw) raw = alert?.raw || null;
  const winSys = raw?.data?.win?.system;
  const winEvt = raw?.data?.win?.eventdata;
  const agentIp = raw?.agent?.ip || raw?.data?.win?.system?.computer?.split(".")?.[0];
  const ruleGroups = raw?.rule?.groups;
  const firedTimes = raw?.rule?.firedtimes;
  const winRating = winSys?.severityValue;
  const message = winSys?.message;

  // Always show if we have basic alert info
  const hasContent = true;

  return (
    <EvidenceBox title="Raw Event Detail" color="#38bdf8">
      <EvidRow label="Host" value={alert?.host} />
      <EvidRow label="Event ID" value={alert?.event_id} />
      <EvidRow label="Rule" value={alert?.rule_description} />
      {message && <EvidRow label="Message" value={String(message).replace(/"/g,"")} highlight />}
      {winEvt?.param1 && <EvidRow label="Service" value={winEvt.param1} />}
      {winEvt?.param2 && winEvt?.param3 && (
        <EvidRow label="Changed" value={`${winEvt.param2} → ${winEvt.param3}`} />
      )}
      {agentIp && <EvidRow label="Machine IP" value={agentIp} />}
      {winRating && <EvidRow label="Windows Rating" value={winRating} />}
      {firedTimes !== undefined && <EvidRow label="Rule fired" value={`${firedTimes} time(s) total`} />}
      {ruleGroups && <EvidRow label="Categories" value={ruleGroups.join(", ")} />}
      {alert?.process && alert.process !== "" && (
        <EvidRow label="Process" value={alert.process} />
      )}
      {alert?.parent_process && alert.parent_process !== "" && (
        <EvidRow label="Parent" value={alert.parent_process} />
      )}
      {alert?.command_line && alert.command_line !== "" && (
        <EvidRow label="Command" value={alert.command_line} highlight />
      )}
    </EvidenceBox>
  );
}

function EvidenceBox({ title, color, children }) {
  return (
    <div style={{background:"rgba(8,18,38,0.95)",border:`1px solid ${color}33`,borderRadius:"10px",padding:"14px"}}>
      <p style={{color,fontSize:"11px",fontWeight:700,textTransform:"uppercase",margin:"0 0 10px",letterSpacing:"0.5px"}}>{title}</p>
      <div style={{display:"flex",flexDirection:"column",gap:"6px"}}>{children}</div>
    </div>
  );
}

function EvidRow({ label, value, highlight }) {
  if (!value || value === "unknown" || value === "-") return null;
  return (
    <div style={{display:"flex",gap:"8px",alignItems:"flex-start"}}>
      <span style={{color:"#475569",fontSize:"11px",minWidth:"90px",flexShrink:0}}>{label}</span>
      <span style={{color: highlight ? "#e2e8f0" : "#94a3b8",fontSize:"11px",lineHeight:"1.4"}}>{value}</span>
    </div>
  );
}

function HostAlertsPanel({ alert, API }) {
  const [others, setOthers] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!alert?.host) { setLoading(false); return; }
    fetch(`${API}/api/host-alerts?host=${encodeURIComponent(alert.host)}&exclude_id=${alert.alert_id || ""}`)
      .then(r => r.json())
      .then(data => { setOthers(Array.isArray(data) ? data.slice(0,8) : []); setLoading(false); })
      .catch(() => setLoading(false));
  }, [alert?.host]);

  const color = others.length >= 3 ? "#ef4444" : others.length > 0 ? "#eab308" : "#22c55e";

  return (
    <EvidenceBox title={`Same Host Alerts — ${alert?.host || ""}`} color={color}>
      {loading ? (
        <span style={{color:"#475569",fontSize:"11px"}}>Loading...</span>
      ) : others.length === 0 ? (
        <span style={{color:"#22c55e",fontSize:"11px"}}>No other alerts from this host — supports FP</span>
      ) : (
        <>
          <div style={{display:"flex",alignItems:"center",gap:"6px",marginBottom:"6px"}}>
            <span style={{color,fontSize:"13px",fontWeight:700}}>{others.length} other alert{others.length===1?"":"s"}</span>
            <span style={{color:"#94a3b8",fontSize:"11px"}}> from this host</span>
          </div>
          {others.map((a,i) => (
            <div key={i} style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",padding:"6px 8px",background:"rgba(255,255,255,0.03)",borderRadius:"6px",gap:"8px"}}>
              <span style={{color:"#cbd5e1",fontSize:"11px",flex:1,lineHeight:"1.4"}}>{a.title || a.rule_description || "Alert"}</span>
              <span style={{color: a.severity==="HIGH"||a.severity==="CRITICAL" ? "#ef4444" : "#eab308",fontSize:"10px",fontWeight:600,flexShrink:0}}>{a.severity}</span>
            </div>
          ))}
          {others.length >= 3 && (
            <p style={{color:"#ef4444",fontSize:"11px",margin:"6px 0 0",fontWeight:600}}>Multiple alerts — strongly supports TP</p>
          )}
        </>
      )}
    </EvidenceBox>
  );
}

function ZeekPanel({ alert, API }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const ip = alert?.raw?.agent?.ip || alert?.source_ip || "";
    const time = alert?.time || "";
    if (!ip) { setLoading(false); return; }
    fetch(`${API}/api/zeek-context?host_ip=${encodeURIComponent(ip)}&alert_time=${encodeURIComponent(time)}&window_minutes=10`)
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [alert?.time]);

  if (loading) return (
    <EvidenceBox title="Zeek Network Context" color="#06b6d4">
      <span style={{color:"#475569",fontSize:"11px"}}>Loading...</span>
    </EvidenceBox>
  );

  if (!data?.available) return (
    <EvidenceBox title="Zeek Network Context" color="#475569">
      <span style={{color:"#475569",fontSize:"11px"}}>No Zeek data available for this time window. Zeek captures live traffic only — historical alerts will not have network context unless Zeek was running at alert time.</span>
    </EvidenceBox>
  );

  return (
    <EvidenceBox title="Zeek Network Context" color="#06b6d4">
      {data.connections.length === 0 && data.dns.length === 0 ? (
        <span style={{color:"#475569",fontSize:"11px"}}>No connections from this host in the alert time window.</span>
      ) : (
        <>
          {data.connections.length > 0 && (
            <>
              <p style={{color:"#64748b",fontSize:"10px",margin:"0 0 4px",fontWeight:600}}>CONNECTIONS ({data.connections.length})</p>
              {data.connections.slice(0,5).map((c,i) => (
                <div key={i} style={{padding:"5px 8px",background:"rgba(6,182,212,0.05)",borderRadius:"5px",fontSize:"11px"}}>
                  <span style={{color:"#38bdf8"}}>{c.src}</span>
                  <span style={{color:"#475569"}}> → </span>
                  <span style={{color:"#e2e8f0"}}>{c.dst}:{c.dst_port}</span>
                  <span style={{color:"#64748b"}}> {c.proto} {c.service && `(${c.service})`} {c.bytes_sent && c.bytes_sent!=="-" ? `${c.bytes_sent}B sent` : ""}</span>
                </div>
              ))}
            </>
          )}
          {data.dns.length > 0 && (
            <>
              <p style={{color:"#64748b",fontSize:"10px",margin:"8px 0 4px",fontWeight:600}}>DNS QUERIES ({data.dns.length})</p>
              {data.dns.slice(0,5).map((d,i) => (
                <div key={i} style={{padding:"5px 8px",background:"rgba(6,182,212,0.05)",borderRadius:"5px",fontSize:"11px"}}>
                  <span style={{color:"#e2e8f0"}}>{d.query}</span>
                  {d.answer && d.answer !== "-" && <span style={{color:"#64748b"}}> → {d.answer}</span>}
                </div>
              ))}
            </>
          )}
        </>
      )}
    </EvidenceBox>
  );
}

function FpTpAssessmentWrapper({ alert, inv, API }) {
  const [otherCount, setOtherCount] = useState(0);
  useEffect(() => {
    if (!alert?.host) return;
    fetch(`${API}/api/host-alerts?host=${encodeURIComponent(alert.host)}&exclude_id=${alert.alert_id || ""}`)
      .then(r => r.json())
      .then(data => setOtherCount(Array.isArray(data) ? data.length : 0))
      .catch(() => {});
  }, [alert?.host]);
  return <FpTpAssessment alert={alert} inv={inv} otherAlertsCount={otherCount} />;
}

function FpTpAssessment({ alert, inv, otherAlertsCount = 0 }) {
  const sev = String(alert?.severity || "LOW").toUpperCase();
  const fpNotes = alert?.fp_notes || inv?.fp_notes || "";
  const chainId = inv?.related_chain_id;
  const confidence = inv?.confidence || "LOW";

  const tpSignals = [];
  const fpSignals = [];

  // Host corroboration — add ONCE
  if (otherAlertsCount >= 3) {
    tpSignals.push(`${otherAlertsCount} other alerts from same host — strongly supports TP`);
  } else if (otherAlertsCount > 0) {
    tpSignals.push(`${otherAlertsCount} other alert(s) from same host — corroborating evidence`);
  } else {
    fpSignals.push("No other alerts from this host — isolated event, supports FP");
  }

  // Severity signals
  if (sev === "CRITICAL") tpSignals.push("CRITICAL severity — near-zero FP rate for this rule");
  else if (sev === "HIGH") tpSignals.push("HIGH severity detection");
  else if (sev === "MEDIUM") fpSignals.push("MEDIUM severity — could be legitimate activity");
  else fpSignals.push("LOW severity — likely benign");

  // Chain signals
  if (chainId) tpSignals.push(`Part of attack chain ${chainId} — corroborated by multiple events`);
  else fpSignals.push("No corroborating attack chain — standalone alert");

  // Confidence
  if (confidence === "HIGH") tpSignals.push("High confidence from correlation engine");
  else if (confidence === "LOW") fpSignals.push("Low confidence from correlation engine");

  // FP notes
  if (fpNotes && !fpNotes.toLowerCase().includes("near-zero")) fpSignals.push(fpNotes);
  if (fpNotes.toLowerCase().includes("near-zero")) tpSignals.push("Rule has near-zero false positive rate");

  // Windows-specific signals
  const raw = alert?.raw;
  if (raw?.data?.win?.system?.severityValue === "INFORMATION") {
    fpSignals.push("Windows rated this event as INFORMATION level");
  }
  if (raw?.rule?.firedtimes === 1) {
    fpSignals.push("Rule has only fired once — not a recurring pattern");
  }

  // Verdict
  let verdict = "NEEDS MORE CONTEXT";
  let color = "#64748b";
  const score = tpSignals.length - fpSignals.length;
  if (sev === "CRITICAL" || score >= 2) { verdict = "LIKELY TP"; color = "#ef4444"; }
  else if (score >= 1 || otherAlertsCount >= 3) { verdict = "POSSIBLE TP"; color = "#f97316"; }
  else if (score <= -2) { verdict = "LEAN FP"; color = "#eab308"; }

  return (
    <EvidenceBox title="FP / TP Assessment" color={color}>
      <div style={{display:"flex",alignItems:"center",gap:"8px",marginBottom:"10px"}}>
        <span style={{color,fontSize:"16px",fontWeight:700}}>{verdict}</span>
      </div>

      {tpSignals.length > 0 && (
        <>
          <p style={{color:"#ef4444",fontSize:"10px",fontWeight:600,margin:"0 0 4px"}}>TRUE POSITIVE SIGNALS</p>
          {tpSignals.map((s,i) => (
            <div key={i} style={{display:"flex",gap:"6px",fontSize:"11px",color:"#fca5a5",marginBottom:"3px"}}>
              <span>+</span><span>{s}</span>
            </div>
          ))}
        </>
      )}

      {fpSignals.length > 0 && (
        <>
          <p style={{color:"#eab308",fontSize:"10px",fontWeight:600,margin:"8px 0 4px"}}>FALSE POSITIVE SIGNALS</p>
          {fpSignals.map((s,i) => (
            <div key={i} style={{display:"flex",gap:"6px",fontSize:"11px",color:"#fde68a",marginBottom:"3px"}}>
              <span>-</span><span>{s}</span>
            </div>
          ))}
        </>
      )}

      <p style={{color:"#475569",fontSize:"10px",margin:"10px 0 0",lineHeight:"1.5"}}>
        {verdict === "LIKELY TP"
          ? "Strong evidence supports a real attack. Escalate and investigate immediately."
          : verdict === "POSSIBLE TP"
          ? "Some evidence of real activity. Correlate with host alerts before deciding."
          : verdict === "LEAN FP"
          ? "Evidence suggests this may be legitimate activity. Verify with change management before closing."
          : "Insufficient evidence to conclude. Review corroborating alerts and raw event detail."}
      </p>
    </EvidenceBox>
  );
}


function StepCard({ step, title, subtitle, color, children }) {
  return (
    <div style={{background:"rgba(8,18,38,0.95)",border:`1px solid ${color}22`,borderRadius:"12px",padding:"20px",marginBottom:"12px",position:"relative"}}>
      <div style={{display:"flex",alignItems:"center",gap:"12px",marginBottom:"16px"}}>
        <div style={{width:"32px",height:"32px",borderRadius:"50%",background:`${color}22`,border:`2px solid ${color}`,display:"flex",alignItems:"center",justifyContent:"center",color:color,fontWeight:700,fontSize:"14px",flexShrink:0}}>{step}</div>
        <div>
          <h3 style={{color:"white",fontSize:"15px",fontWeight:700,margin:0}}>{title}</h3>
          <p style={{color:"#64748b",fontSize:"12px",margin:0}}>{subtitle}</p>
        </div>
      </div>
      {children}
    </div>
  );
}

function InfoBox({ label, value, icon }) {
  return (
    <div style={{background:"rgba(255,255,255,0.03)",border:"1px solid rgba(255,255,255,0.07)",borderRadius:"8px",padding:"10px 14px"}}>
      <p style={{color:"#475569",fontSize:"10px",textTransform:"uppercase",letterSpacing:"0.5px",margin:"0 0 4px"}}>{icon} {label}</p>
      <p style={{color:"#e2e8f0",fontSize:"13px",fontWeight:600,margin:0,wordBreak:"break-all"}}>{value || "N/A"}</p>
    </div>
  );
}

function Tag({ label, color }) {
  return (
    <span style={{background:`${color}18`,border:`1px solid ${color}44`,color:color,padding:"4px 10px",borderRadius:"6px",fontSize:"11px",fontWeight:600}}>{label}</span>
  );
}

function FindingBox({ title, icon, items, color }) {
  return (
    <div style={{background:"rgba(255,255,255,0.03)",border:`1px solid ${color}33`,borderRadius:"10px",padding:"14px"}}>
      <p style={{color:color,fontSize:"12px",fontWeight:700,margin:"0 0 10px",textTransform:"uppercase"}}>{icon} {title}</p>
      <ul style={{margin:0,paddingLeft:"18px",display:"grid",gap:"6px"}}>
        {(items || []).map((item, i) => (
          <li key={i} style={{color:"#cbd5e1",fontSize:"12px",lineHeight:"1.4"}}>{item}</li>
        ))}
      </ul>
    </div>
  );
}

function MetricBox({ label, value, color }) {
  return (
    <div style={{background:"rgba(255,255,255,0.03)",border:"1px solid rgba(255,255,255,0.07)",borderRadius:"8px",padding:"12px 14px",textAlign:"center"}}>
      <p style={{color:"#475569",fontSize:"10px",textTransform:"uppercase",letterSpacing:"0.5px",margin:"0 0 6px"}}>{label}</p>
      <p style={{color:color,fontSize:"18px",fontWeight:700,margin:0}}>{value}</p>
    </div>
  );
}

function VerdictBtn({ label, sub, color, onClick }) {
  return (
    <button onClick={onClick} style={{background:`${color}0f`,border:`1px solid ${color}44`,borderRadius:"10px",padding:"16px",cursor:"pointer",textAlign:"left",transition:"all 0.2s",width:"100%"}}>
      <p style={{color:color,fontWeight:700,fontSize:"13px",margin:"0 0 4px"}}>{label}</p>
      <p style={{color:"#64748b",fontSize:"11px",margin:0}}>{sub}</p>
    </button>
  );
}
