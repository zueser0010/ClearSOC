import { useEffect, useMemo, useState } from "react";
import { FileText, Download, RefreshCw, ShieldAlert } from "lucide-react";

const API = "http://localhost:8001";

function fmt(t) {
  if (!t) return "N/A";
  return String(t).replace("T", " ").split("+")[0].slice(0, 19);
}

function sevColor(s) {
  s = String(s || "LOW").toUpperCase();
  if (s === "CRITICAL") return "#ef4444";
  if (s === "HIGH") return "#f97316";
  if (s === "MEDIUM") return "#eab308";
  return "#22c55e";
}

export default function Reports() {
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [chains, setChains] = useState([]);
  const [selectedType, setSelectedType] = useState("INCIDENT");
  const [selectedId, setSelectedId] = useState("");

  async function loadData() {
    try {
      const [a, i, c] = await Promise.all([
        fetch(`${API}/api/alerts`).then(r => r.json()),
        fetch(`${API}/api/incidents`).then(r => r.json()),
        fetch(`${API}/api/attack-chains`).then(r => r.json()),
      ]);
      setAlerts(Array.isArray(a) ? a : []);
      setIncidents(Array.isArray(i) ? i : []);
      setChains(Array.isArray(c) ? c : []);
    } catch {
      setAlerts([]);
      setIncidents([]);
      setChains([]);
    }
  }

  useEffect(() => {
    loadData();
  }, []);

  const sourceList = useMemo(() => {
    if (selectedType === "ALERT") return alerts;
    if (selectedType === "CHAIN") return chains;
    return incidents;
  }, [selectedType, alerts, incidents, chains]);

  const selected = sourceList.find((x, idx) => getId(x, idx, selectedType) === selectedId) || sourceList[0];

  useEffect(() => {
    if (sourceList.length) setSelectedId(getId(sourceList[0], 0, selectedType));
  }, [selectedType, sourceList.length]);

  const report = buildReport(selected, selectedType);

  function downloadReport() {
    const blob = new Blob([report], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ClearSOC_${selectedType}_Report_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div style={{padding:"24px",color:"#e2e8f0"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:"18px"}}>
        <div>
          <h1 style={{fontSize:"32px",margin:0,color:"#f8fafc"}}>Reports</h1>
          <p style={{color:"#94a3b8",margin:"4px 0"}}>Generate analyst-ready SOC reports from alerts, incidents, and attack chains</p>
        </div>

        <button onClick={loadData} style={btn}>
          <RefreshCw size={16}/> Refresh
        </button>
      </div>

      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:"14px",marginBottom:"16px"}}>
        <Kpi label="Alerts Available" value={alerts.length} color="#38bdf8"/>
        <Kpi label="Incidents Available" value={incidents.length} color="#eab308"/>
        <Kpi label="Attack Chains" value={chains.length} color="#ef4444"/>
        <Kpi label="Report Type" value={selectedType} color="#a855f7"/>
      </div>

      <div style={{display:"grid",gridTemplateColumns:"260px 1fr 180px",gap:"12px",background:"rgba(8,18,38,0.95)",border:"1px solid rgba(56,189,248,0.18)",borderRadius:"14px",padding:"14px",marginBottom:"16px"}}>
        <select value={selectedType} onChange={e=>setSelectedType(e.target.value)} style={select}>
          <option value="INCIDENT">Incident Report</option>
          <option value="CHAIN">Attack Chain Report</option>
          <option value="ALERT">Alert Report</option>
        </select>

        <select value={selectedId} onChange={e=>setSelectedId(e.target.value)} style={select}>
          {sourceList.map((x, idx) => (
            <option key={idx} value={getId(x, idx, selectedType)}>
              {getTitle(x, idx, selectedType)}
            </option>
          ))}
        </select>

        <button onClick={downloadReport} style={btn}>
          <Download size={16}/> Download
        </button>
      </div>

      <div style={{display:"grid",gridTemplateColumns:"1fr 1.2fr",gap:"16px"}}>
        <div style={{background:"rgba(8,18,38,0.95)",border:"1px solid rgba(56,189,248,0.18)",borderRadius:"14px",padding:"16px"}}>
          <h3 style={{color:"#f8fafc",margin:"0 0 12px"}}><ShieldAlert size={18}/> Report Summary</h3>
          <Summary selected={selected} type={selectedType}/>
        </div>

        <div style={{background:"#020617",border:"1px solid rgba(56,189,248,0.18)",borderRadius:"14px",overflow:"hidden"}}>
          <div style={{padding:"12px 16px",borderBottom:"1px solid rgba(148,163,184,0.12)",display:"flex",justifyContent:"space-between"}}>
            <span style={{color:"#93c5fd",fontWeight:800}}><FileText size={16}/> Report Preview</span>
            <span style={{color:"#64748b",fontSize:"12px"}}>TXT export</span>
          </div>
          <pre style={{margin:0,padding:"18px",whiteSpace:"pre-wrap",fontSize:"12px",lineHeight:"1.6",color:"#cbd5e1",maxHeight:"650px",overflow:"auto"}}>
            {report || "No report data available"}
          </pre>
        </div>
      </div>
    </div>
  );
}

function getId(x, idx, type) {
  if (!x) return "";
  if (type === "ALERT") return x.alert_id || `ALERT-${idx}`;
  if (type === "CHAIN") return x.chain_id || `CHAIN-${idx}`;
  return x.incident_id || `INC-${idx}`;
}

function getTitle(x, idx, type) {
  if (!x) return "No data";
  if (type === "ALERT") return `${x.alert_id || idx} | ${x.title || x.rule_name || x.rule_description || "Alert"}`;
  if (type === "CHAIN") return `${x.chain_id || idx} | ${x.chain_label || x.chain_type || "Attack Chain"}`;
  return `${x.incident_id || `INC-${idx}`} | ${x.chain_type || x.module || "Incident"}`;
}

function buildReport(x, type) {
  if (!x) return "";

  if (type === "ALERT") {
    return `CLEARSOC ALERT REPORT
=====================

Report Type: Alert Investigation
Generated: ${new Date().toLocaleString()}

1. EXECUTIVE SUMMARY
Alert: ${x.title || x.rule_name || x.rule_description || "Security Alert"}
Severity: ${x.severity || "N/A"}
Host: ${x.host || "N/A"}
User: ${x.user || "N/A"}
Time: ${fmt(x.time)}
Event ID: ${x.event_id || "N/A"}

2. WHY THIS ALERT TRIGGERED
${x.summary || x.rule_description || "Security event matched ClearSOC detection logic."}

3. MITRE ATT&CK MAPPING
${Array.isArray(x.mitre) ? x.mitre.join(", ") : "N/A"}

4. RECOMMENDED ACTIONS
${(x.recommended_actions || ["Review raw event", "Validate user and host context", "Decide false positive, monitor, or escalate"]).map((a,i)=>`${i+1}. ${a}`).join("\n")}

5. ANALYST CONCLUSION
This alert should be validated using surrounding events, user context, source IP, and related attack-chain activity.
`;
  }

  if (type === "CHAIN") {
    const timeline = x.timeline || [];
    return `CLEARSOC ATTACK CHAIN REPORT
============================

Report Type: Correlated Attack Chain
Generated: ${new Date().toLocaleString()}

1. EXECUTIVE SUMMARY
Chain: ${x.chain_label || x.chain_type || "Attack Chain"}
Severity: ${x.severity || "N/A"}
Confidence: ${x.confidence || "N/A"}
Decision: ${x.decision || "N/A"}
Host: ${x.host || "N/A"}
User: ${x.user || "N/A"}
Alert Count: ${x.alert_count || timeline.length || "N/A"}

2. WHY THIS MATTERS
${(x.reasons || ["Multiple security events were correlated into one possible attack chain."]).join("\n")}

3. MITRE ATT&CK MAPPING
${Array.isArray(x.mitre) ? x.mitre.join(", ") : "N/A"}

4. TIMELINE
${timeline.length ? timeline.map((t,i)=>`${i+1}. ${fmt(t.time)} | ${t.stage || t.kill_chain_phase || "Event"} | ${t.event || ""} | ${t.details || ""}`).join("\n") : "No timeline available"}

5. RECOMMENDED ACTIONS
${(x.recommended_actions || ["Review each chain event", "Validate if activity is authorized", "Escalate if compromise is confirmed"]).map((a,i)=>`${i+1}. ${a}`).join("\n")}

6. ANALYST CONCLUSION
The chain should be investigated as a grouped security story rather than separate isolated alerts.
`;
  }

  const timeline = x.timeline || [];
  return `CLEARSOC INCIDENT REPORT
========================

Report Type: Incident Case
Generated: ${new Date().toLocaleString()}

1. EXECUTIVE SUMMARY
Incident: ${x.chain_type || x.module || "Security Incident"}
Severity: ${x.severity || "N/A"}
Risk Score: ${x.risk_score || "N/A"}
Confidence: ${x.correlation_confidence || x.confidence || "N/A"}
Host: ${x.host || x.destination_host || "N/A"}
User: ${x.user || "N/A"}
Source IP: ${x.source_ip || "N/A"}

2. INCIDENT SUMMARY
${x.kill_chain_summary || x.summary || "No summary available."}

3. WHY THIS BECAME AN INCIDENT
${(x.reasons || ["Multiple alerts were correlated into a single investigation case."]).map((r,i)=>`${i+1}. ${r}`).join("\n")}

4. MITRE ATT&CK MAPPING
${Array.isArray(x.mitre) ? x.mitre.join(", ") : "N/A"}

5. INCIDENT TIMELINE
${timeline.length ? timeline.map((t,i)=>`${i+1}. ${fmt(t.time)} | ${t.stage || "Event"} | ${t.event || ""} | ${t.details || ""}`).join("\n") : "No timeline available"}

6. RECOMMENDED ACTIONS
${(x.recommended_actions || ["Validate source IP", "Review related alerts", "Monitor for successful login or escalation"]).map((a,i)=>`${i+1}. ${a}`).join("\n")}

7. ANALYST CONCLUSION
Current evidence should be reviewed before declaring true positive. Use this report to support FP / Monitor / Escalate decision.
`;
}

function Summary({ selected, type }) {
  if (!selected) return <p style={{color:"#64748b"}}>No item selected.</p>;

  const sev = selected.severity || "LOW";
  const color = sevColor(sev);

  return (
    <div style={{display:"grid",gap:"10px"}}>
      <Mini label="Type" value={type}/>
      <Mini label="Title" value={selected.title || selected.chain_label || selected.chain_type || selected.module || selected.rule_description || "N/A"}/>
      <Mini label="Severity" value={sev} color={color}/>
      <Mini label="Host" value={selected.host || selected.destination_host || "N/A"}/>
      <Mini label="User" value={selected.user || "N/A"}/>
      <Mini label="MITRE" value={Array.isArray(selected.mitre) ? selected.mitre.join(", ") : "N/A"}/>
    </div>
  );
}

function Kpi({ label, value, color }) {
  return (
    <div style={{background:"rgba(8,18,38,0.94)",border:`1px solid ${color}33`,borderRadius:"14px",padding:"16px"}}>
      <p style={{margin:"0 0 8px",color:"#94a3b8",fontSize:"12px",textTransform:"uppercase"}}>{label}</p>
      <h2 style={{margin:0,fontSize:"28px",color}}>{value}</h2>
    </div>
  );
}

function Mini({ label, value, color }) {
  return (
    <div style={{background:"rgba(255,255,255,0.03)",border:"1px solid rgba(255,255,255,0.07)",borderRadius:"8px",padding:"10px"}}>
      <p style={{margin:"0 0 5px",color:"#64748b",fontSize:"10px",textTransform:"uppercase"}}>{label}</p>
      <p style={{margin:0,color:color || "#e2e8f0",fontSize:"12px",fontWeight:800,wordBreak:"break-word"}}>{value}</p>
    </div>
  );
}

const btn = {
  display:"flex",
  alignItems:"center",
  justifyContent:"center",
  gap:"8px",
  background:"rgba(14,165,233,0.16)",
  border:"1px solid rgba(56,189,248,0.4)",
  color:"#e0f2fe",
  borderRadius:"8px",
  padding:"10px 14px",
  fontWeight:700,
  cursor:"pointer"
};

const select = {
  background:"#071426",
  color:"#e2e8f0",
  border:"1px solid rgba(56,189,248,0.25)",
  borderRadius:"10px",
  padding:"10px"
};
