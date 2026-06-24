import { useEffect, useMemo, useState } from "react";
import { Search, RefreshCw, Shield, ExternalLink } from "lucide-react";

const API = "http://localhost:8001";

const MITRE_DB = {
  "T1110":     { name:"Brute Force",                    tactic:"Credential Access",   plain:"Attacker repeatedly tries passwords to break into an account",                          color:"#ef4444" },
  "T1110.001": { name:"Password Guessing",              tactic:"Credential Access",   plain:"Attacker guesses common passwords like Password123",                                    color:"#ef4444" },
  "T1078":     { name:"Valid Accounts",                 tactic:"Initial Access",      plain:"Attacker uses stolen or compromised credentials to log in",                            color:"#f97316" },
  "T1078.002": { name:"Domain Accounts",                tactic:"Privilege Escalation",plain:"Attacker uses domain admin account to access multiple systems",                        color:"#ef4444" },
  "T1059":     { name:"Command & Scripting",            tactic:"Execution",           plain:"Attacker runs malicious commands or scripts on the system",                            color:"#f97316" },
  "T1059.001": { name:"PowerShell",                     tactic:"Execution",           plain:"Attacker uses PowerShell to run hidden malicious commands",                            color:"#f97316" },
  "T1059.003": { name:"Windows Command Shell",          tactic:"Execution",           plain:"Attacker uses cmd.exe to run commands — often spawned by unusual processes",          color:"#f97316" },
  "T1070.004": { name:"File Deletion",                  tactic:"Defense Evasion",     plain:"Attacker deletes files to hide their tracks and avoid detection",                     color:"#eab308" },
  "T1082":     { name:"System Information Discovery",   tactic:"Discovery",           plain:"Attacker checks what OS, software, and configs are on the system",                    color:"#eab308" },
  "T1087":     { name:"Account Discovery",              tactic:"Discovery",           plain:"Attacker lists all user accounts to find targets for lateral movement",               color:"#eab308" },
  "T1105":     { name:"Ingress Tool Transfer",          tactic:"Command and Control", plain:"Attacker downloads malicious tools or files onto the compromised system",             color:"#ef4444" },
  "T1136":     { name:"Create Account",                 tactic:"Persistence",         plain:"Attacker creates a backdoor account to maintain access even after discovery",         color:"#ef4444" },
  "T1136.001": { name:"Local Account Creation",         tactic:"Persistence",         plain:"Attacker creates a local Windows account as a persistent backdoor",                   color:"#ef4444" },
  "T1098":     { name:"Account Manipulation",           tactic:"Persistence",         plain:"Attacker modifies accounts or adds them to admin groups to maintain control",         color:"#ef4444" },
  "T1003":     { name:"Credential Dumping",             tactic:"Credential Access",   plain:"Attacker steals password hashes from memory (Mimikatz) — very dangerous",            color:"#ef4444" },
  "T1021":     { name:"Remote Services",                tactic:"Lateral Movement",    plain:"Attacker moves to other computers using RDP, SMB, or other remote protocols",        color:"#ef4444" },
  "T1543.003": { name:"Windows Service",                tactic:"Persistence",         plain:"Attacker installs a malicious Windows service that starts automatically on boot",     color:"#ef4444" },
  "T1562.002": { name:"Disable Windows Event Logging",  tactic:"Defense Evasion",     plain:"Attacker turns off audit logging to hide their actions from defenders",              color:"#ef4444" },
  "T1550.002": { name:"Pass the Hash",                  tactic:"Lateral Movement",    plain:"Attacker uses stolen password hashes to authenticate without knowing the password",  color:"#ef4444" },
  "T1531":     { name:"Account Access Removal",         tactic:"Impact",              plain:"Attacker locks out legitimate users to disrupt operations",                           color:"#ef4444" },
  "T1548":     { name:"Abuse Elevation Control",        tactic:"Privilege Escalation",plain:"Attacker bypasses UAC or sudo to gain admin privileges",                              color:"#f97316" },
  "T1548.003": { name:"Sudo and Sudo Caching",          tactic:"Privilege Escalation",plain:"Attacker abuses sudo permissions on Linux to run commands as root",                   color:"#f97316" },
};

const TACTIC_COLOR = {
  "Initial Access":       "#3b82f6",
  "Execution":            "#f97316",
  "Persistence":          "#ef4444",
  "Privilege Escalation": "#a855f7",
  "Defense Evasion":      "#eab308",
  "Credential Access":    "#ef4444",
  "Discovery":            "#06b6d4",
  "Lateral Movement":     "#f97316",
  "Command and Control":  "#ec4899",
  "Impact":               "#ef4444",
  "Unknown":              "#475569",
};

const SEV_COLOR = { CRITICAL:"#ef4444", HIGH:"#f97316", MEDIUM:"#eab308", LOW:"#22c55e", INFO:"#3b82f6" };

function sevRank(s) {
  return { CRITICAL:4, HIGH:3, MEDIUM:2, LOW:1, INFO:0 }[String(s||"INFO").toUpperCase()] ?? 0;
}

export default function Mitre() {
  const [alerts, setAlerts] = useState([]);
  const [search, setSearch] = useState("");
  const [tacticFilter, setTacticFilter] = useState("ALL");
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(null);

  async function loadData() {
    setLoading(true);
    try {
      const res = await fetch(`${API}/api/alerts`);
      const data = await res.json();
      setAlerts(Array.isArray(data) ? data : []);
    } catch { setAlerts([]); }
    finally { setLoading(false); }
  }

  useEffect(() => { loadData(); }, []);

  const rows = useMemo(() => {
    const map = {};
    alerts.forEach(a => {
      const ids = Array.isArray(a.mitre) ? a.mitre : [];
      ids.forEach(id => {
        if (!map[id]) {
          const meta = MITRE_DB[id] || { name:"Unknown Technique", tactic:"Unknown", plain:"No description available", color:"#475569" };
          map[id] = { id, ...meta, count:0, highestSeverity:"INFO", hosts:new Set(), users:new Set(), alerts:[] };
        }
        map[id].count++;
        map[id].hosts.add(a.host);
        map[id].users.add(a.user);
        if (sevRank(a.severity) > sevRank(map[id].highestSeverity)) map[id].highestSeverity = a.severity;
        if (map[id].alerts.length < 5) map[id].alerts.push(a);
      });
    });
    return Object.values(map).sort((a,b) => b.count - a.count);
  }, [alerts]);

  const tactics = useMemo(() => ["ALL", ...new Set(rows.map(r => r.tactic).filter(t => t !== "Unknown"))].sort(), [rows]);

  const filtered = rows.filter(r => {
    const q = search.toLowerCase().trim();
    const matchSearch = !q || r.id.toLowerCase().includes(q) || r.name.toLowerCase().includes(q) || r.tactic.toLowerCase().includes(q) || r.plain.toLowerCase().includes(q);
    const matchTactic = tacticFilter === "ALL" || r.tactic === tacticFilter;
    return matchSearch && matchTactic;
  });

  const totalMappings = rows.reduce((a,b) => a + b.count, 0);
  const highRisk = rows.filter(r => ["HIGH","CRITICAL"].includes(r.highestSeverity)).length;

  return (
    <div style={{padding:"20px",color:"#e2e8f0"}}>

      {/* HEADER */}
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:"20px"}}>
        <div>
          <h1 style={{fontSize:"24px",fontWeight:700,color:"white",margin:0}}>🎯 MITRE ATT&CK Coverage</h1>
          <p style={{color:"#64748b",fontSize:"13px",margin:"4px 0 0"}}>Attack techniques detected in your environment — mapped to the MITRE ATT&CK framework</p>
        </div>
        <button onClick={loadData} style={{display:"flex",alignItems:"center",gap:"6px",background:"rgba(56,189,248,0.1)",border:"1px solid rgba(56,189,248,0.3)",color:"#38bdf8",padding:"8px 14px",borderRadius:"8px",cursor:"pointer",fontSize:"13px"}}>
          <RefreshCw size={14}/> Refresh
        </button>
      </div>

      {/* KPI CARDS */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:"12px",marginBottom:"20px"}}>
        {[
          {label:"Techniques Detected", value:rows.length, color:"#38bdf8", desc:"Unique ATT&CK techniques found"},
          {label:"Total Alert Mappings", value:totalMappings, color:"#a855f7", desc:"Alerts mapped to techniques"},
          {label:"High Risk Techniques", value:highRisk, color:"#ef4444", desc:"Techniques with HIGH/CRITICAL alerts"},
          {label:"Total Alerts", value:alerts.length, color:"#f97316", desc:"Alerts analyzed"},
        ].map(k => (
          <div key={k.label} style={{background:"rgba(8,18,38,0.95)",border:`1px solid ${k.color}33`,borderRadius:"12px",padding:"16px"}}>
            <p style={{color:"#64748b",fontSize:"11px",margin:"0 0 4px",textTransform:"uppercase",letterSpacing:"0.5px"}}>{k.label}</p>
            <h2 style={{color:k.color,fontSize:"28px",fontWeight:700,margin:"0 0 4px"}}>{k.value}</h2>
            <p style={{color:"#475569",fontSize:"11px",margin:0}}>{k.desc}</p>
          </div>
        ))}
      </div>

      {/* TACTIC FILTER BUTTONS */}
      <div style={{marginBottom:"16px"}}>
        <p style={{color:"#64748b",fontSize:"11px",margin:"0 0 8px",textTransform:"uppercase",letterSpacing:"0.5px"}}>Filter by Tactic</p>
        <div style={{display:"flex",gap:"6px",flexWrap:"wrap"}}>
          {tactics.map(t => {
            const color = TACTIC_COLOR[t] || "#475569";
            const active = tacticFilter === t;
            return (
              <button key={t} onClick={() => setTacticFilter(t)}
                style={{background: active ? `${color}22` : "rgba(255,255,255,0.03)",
                  border:`1px solid ${active ? color : "rgba(255,255,255,0.08)"}`,
                  color: active ? color : "#475569",
                  padding:"6px 12px",borderRadius:"6px",cursor:"pointer",fontSize:"12px",fontWeight:600}}>
                {t === "ALL" ? "All Tactics" : t}
              </button>
            );
          })}
        </div>
      </div>

      {/* SEARCH */}
      <div style={{display:"flex",alignItems:"center",gap:"10px",background:"rgba(8,18,38,0.95)",border:"1px solid rgba(255,255,255,0.08)",borderRadius:"8px",padding:"10px 14px",marginBottom:"16px"}}>
        <Search size={14} color="#475569"/>
        <input value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Search technique ID, name, tactic, or plain English description..."
          style={{background:"transparent",border:"none",outline:"none",color:"#e2e8f0",fontSize:"13px",width:"100%"}}
        />
      </div>

      {/* TECHNIQUE CARDS */}
      {loading ? (
        <div style={{textAlign:"center",padding:"40px",color:"#475569"}}>Loading MITRE coverage...</div>
      ) : filtered.length === 0 ? (
        <div style={{textAlign:"center",padding:"40px",color:"#475569"}}>No techniques found</div>
      ) : (
        <div style={{display:"flex",flexDirection:"column",gap:"8px"}}>
          {filtered.map((r, i) => {
            const tacticColor = TACTIC_COLOR[r.tactic] || "#475569";
            const sevColor = SEV_COLOR[r.highestSeverity] || "#94a3b8";
            const isExpanded = expanded === r.id;

            return (
              <div key={i} style={{background:"rgba(8,18,38,0.95)",border:`1px solid ${sevColor}22`,borderRadius:"12px",overflow:"hidden",transition:"all 0.2s"}}>

                {/* MAIN ROW */}
                <div onClick={() => setExpanded(isExpanded ? null : r.id)}
                  style={{padding:"16px",cursor:"pointer",display:"grid",gridTemplateColumns:"140px 1fr 180px 80px 80px 80px 120px",gap:"12px",alignItems:"center"}}>

                  {/* Technique ID */}
                  <div style={{display:"flex",flexDirection:"column",gap:"4px"}}>
                    <a href={`https://attack.mitre.org/techniques/${r.id.replace(".","/")}/ `}
                      target="_blank" rel="noreferrer"
                      onClick={e => e.stopPropagation()}
                      style={{color:"#38bdf8",fontWeight:700,fontSize:"13px",textDecoration:"none",fontFamily:"monospace",display:"flex",alignItems:"center",gap:"4px"}}>
                      {r.id} <ExternalLink size={10}/>
                    </a>
                    <span style={{color:"#475569",fontSize:"10px"}}>Click to expand</span>
                  </div>

                  {/* Name + Plain English */}
                  <div>
                    <p style={{color:"#e2e8f0",fontWeight:600,fontSize:"13px",margin:"0 0 4px"}}>{r.name}</p>
                    <p style={{color:"#64748b",fontSize:"11px",margin:0,lineHeight:"1.4"}}>{r.plain}</p>
                  </div>

                  {/* Tactic */}
                  <span style={{background:`${tacticColor}18`,border:`1px solid ${tacticColor}44`,color:tacticColor,padding:"4px 10px",borderRadius:"6px",fontSize:"11px",fontWeight:600,textAlign:"center"}}>
                    {r.tactic}
                  </span>

                  {/* Alert count */}
                  <div style={{textAlign:"center"}}>
                    <p style={{color:"#94a3b8",fontSize:"10px",margin:"0 0 2px",textTransform:"uppercase"}}>Alerts</p>
                    <p style={{color:"#e2e8f0",fontWeight:700,fontSize:"16px",margin:0}}>{r.count}</p>
                  </div>

                  {/* Hosts */}
                  <div style={{textAlign:"center"}}>
                    <p style={{color:"#94a3b8",fontSize:"10px",margin:"0 0 2px",textTransform:"uppercase"}}>Hosts</p>
                    <p style={{color:"#e2e8f0",fontWeight:700,fontSize:"16px",margin:0}}>{[...r.hosts].filter(Boolean).length}</p>
                  </div>

                  {/* Users */}
                  <div style={{textAlign:"center"}}>
                    <p style={{color:"#94a3b8",fontSize:"10px",margin:"0 0 2px",textTransform:"uppercase"}}>Users</p>
                    <p style={{color:"#e2e8f0",fontWeight:700,fontSize:"16px",margin:0}}>{[...r.users].filter(Boolean).length}</p>
                  </div>

                  {/* Severity */}
                  <div style={{textAlign:"center"}}>
                    <p style={{color:"#94a3b8",fontSize:"10px",margin:"0 0 4px",textTransform:"uppercase"}}>Risk Level</p>
                    <span style={{background:`${sevColor}22`,border:`1px solid ${sevColor}`,color:sevColor,padding:"4px 10px",borderRadius:"6px",fontSize:"11px",fontWeight:700}}>
                      {r.highestSeverity}
                    </span>
                  </div>
                </div>

                {/* EXPANDED DETAILS */}
                {isExpanded && (
                  <div style={{borderTop:"1px solid rgba(255,255,255,0.06)",padding:"16px",background:"rgba(0,0,0,0.2)"}}>
                    <p style={{color:"#64748b",fontSize:"11px",fontWeight:600,textTransform:"uppercase",margin:"0 0 12px",letterSpacing:"0.5px"}}>
                      🔍 Detected Alerts for {r.id}
                    </p>
                    <div style={{display:"flex",flexDirection:"column",gap:"8px"}}>
                      {r.alerts.map((a, j) => (
                        <div key={j} style={{background:"rgba(255,255,255,0.03)",border:"1px solid rgba(255,255,255,0.06)",borderRadius:"8px",padding:"10px 14px",display:"flex",justifyContent:"space-between",alignItems:"center",gap:"12px",flexWrap:"wrap"}}>
                          <div>
                            <p style={{color:"#e2e8f0",fontSize:"12px",fontWeight:600,margin:"0 0 4px"}}>{a.title}</p>
                            <p style={{color:"#64748b",fontSize:"11px",margin:0}}>{a.summary}</p>
                          </div>
                          <div style={{display:"flex",gap:"8px",alignItems:"center",flexShrink:0}}>
                            <span style={{color:"#94a3b8",fontSize:"11px"}}>{a.host}</span>
                            <span style={{color:"#475569",fontSize:"11px"}}>{a.user}</span>
                            <span style={{color:SEV_COLOR[a.severity]||"#94a3b8",fontWeight:700,fontSize:"11px"}}>{a.severity}</span>
                          </div>
                        </div>
                      ))}
                    </div>

                    <div style={{marginTop:"12px",padding:"12px",background:"rgba(56,189,248,0.05)",border:"1px solid rgba(56,189,248,0.1)",borderRadius:"8px"}}>
                      <p style={{color:"#38bdf8",fontSize:"12px",fontWeight:600,margin:"0 0 6px"}}>💡 What this means for your environment</p>
                      <p style={{color:"#94a3b8",fontSize:"12px",margin:0,lineHeight:"1.6"}}>{r.plain}. This technique was observed {r.count} time(s) across {[...r.hosts].filter(Boolean).length} host(s). {r.highestSeverity === "CRITICAL" || r.highestSeverity === "HIGH" ? "Immediate investigation recommended." : "Monitor for escalation patterns."}</p>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* FOOTER NOTE */}
      <div style={{display:"flex",alignItems:"center",gap:"8px",marginTop:"20px",padding:"14px",background:"rgba(56,189,248,0.05)",border:"1px solid rgba(56,189,248,0.1)",borderRadius:"8px"}}>
        <Shield size={16} color="#38bdf8"/>
        <span style={{color:"#64748b",fontSize:"12px"}}>Coverage is calculated from active ClearSOC alerts. Run more attack scenarios to increase technique coverage. Click any technique to see detected alerts.</span>
      </div>
    </div>
  );
}
