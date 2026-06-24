import { useEffect, useMemo, useState } from "react";
import { Search, RefreshCw, Copy, ExternalLink } from "lucide-react";

const API = "http://localhost:8001";

function cleanValue(v) {
  if (!v) return "";
  return String(v).trim();
}

function addIOC(map, type, value, source) {
  value = cleanValue(value);
  if (!value || value === "-" || value.toLowerCase() === "unknown" || value === "127.0.0.1") return;

  const key = `${type}:${value}`;

  if (!map[key]) {
    map[key] = {
      type,
      value,
      count: 0,
      hosts: new Set(),
      users: new Set(),
      alerts: [],
      mitre: new Set(),
      severity: "INFO",
      firstSeen: source.time || source.timestamp || "",
      lastSeen: source.time || source.timestamp || "",
    };
  }

  map[key].count += 1;

  if (source.host) map[key].hosts.add(source.host);
  if (source.user) map[key].users.add(source.user);

  if (Array.isArray(source.mitre)) {
    source.mitre.forEach(m => map[key].mitre.add(m));
  }

  if (source.title || source.rule_description || source.summary) {
    map[key].alerts.push(source.title || source.rule_description || source.summary);
  }

  const sevRank = { CRITICAL:5, HIGH:4, MEDIUM:3, LOW:2, INFO:1 };
  const sev = String(source.severity || "INFO").toUpperCase();

  if ((sevRank[sev] || 1) > (sevRank[map[key].severity] || 1)) {
    map[key].severity = sev;
  }

  const t = source.time || source.timestamp || "";
  if (t) {
    if (!map[key].firstSeen || t < map[key].firstSeen) map[key].firstSeen = t;
    if (!map[key].lastSeen || t > map[key].lastSeen) map[key].lastSeen = t;
  }
}

function formatTime(v) {
  if (!v) return "N/A";
  const d = new Date(v);
  if (isNaN(d.getTime())) return v;
  return d.toLocaleString();
}

function iocLink(type, value) {
  if (type === "IP") return `https://www.abuseipdb.com/check/${value}`;
  if (type === "DOMAIN") return `https://www.virustotal.com/gui/domain/${value}`;
  if (type === "HASH") return `https://www.virustotal.com/gui/file/${value}`;
  return null;
}

export default function IOCs() {
  const [alerts, setAlerts] = useState([]);
  const [rawLogs, setRawLogs] = useState([]);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("ALL");
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState("");

  async function loadData() {
    setLoading(true);
    try {
      const [aRes, rRes] = await Promise.all([
        fetch(`${API}/api/alerts`),
        fetch(`${API}/api/raw-logs?limit=3000`)
      ]);

      const a = await aRes.json();
      const r = await rRes.json();

      setAlerts(Array.isArray(a) ? a : []);
      setRawLogs(Array.isArray(r) ? r : (r.logs || []));
      setLastRefresh(new Date().toLocaleString());
    } catch (e) {
      console.error("Failed to load IOC data:", e);
      setAlerts([]);
      setRawLogs([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  }, []);

  const iocs = useMemo(() => {
    const map = {};

    const all = [...alerts, ...rawLogs];

    all.forEach(e => {
      addIOC(map, "IP", e.source_ip || e.src_ip || e.ipAddress, e);
      addIOC(map, "HOST", e.host, e);
      addIOC(map, "USER", e.user, e);

      if (e.process) {
        const proc = String(e.process).split("\\").pop();
        addIOC(map, "PROCESS", proc, e);
      }

      if (e.parent_process) {
        const parent = String(e.parent_process).split("\\").pop();
        addIOC(map, "PROCESS", parent, e);
      }

      const cmd = String(e.command_line || "");
      const domainMatches = cmd.match(/\b([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g) || [];
      domainMatches.forEach(d => addIOC(map, "DOMAIN", d, e));

      const hashMatches = cmd.match(/\b[a-fA-F0-9]{32,64}\b/g) || [];
      hashMatches.forEach(h => addIOC(map, "HASH", h, e));
    });

    return Object.values(map).sort((a, b) => b.count - a.count);
  }, [alerts, rawLogs]);

  const filtered = iocs.filter(i => {
    const q = search.toLowerCase().trim();

    const matchSearch =
      !q ||
      i.value.toLowerCase().includes(q) ||
      i.type.toLowerCase().includes(q) ||
      [...i.hosts].join(" ").toLowerCase().includes(q) ||
      [...i.users].join(" ").toLowerCase().includes(q) ||
      [...i.mitre].join(" ").toLowerCase().includes(q);

    const matchType = typeFilter === "ALL" || i.type === typeFilter;

    return matchSearch && matchType;
  });

  const types = ["ALL", ...new Set(iocs.map(i => i.type))];

  const highRisk = iocs.filter(i =>
    ["IP", "DOMAIN", "HASH", "PROCESS"].includes(i.type) &&
    ["HIGH", "CRITICAL"].includes(String(i.severity).toUpperCase())
  ).length;

  function copyValue(value) {
    navigator.clipboard.writeText(value);
  }

  return (
    <div className="page" style={{padding:"24px",color:"#e2e8f0"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:"18px"}}>
        <div>
          <h1 style={{fontSize:"32px",margin:0,color:"#f8fafc"}}>Indicators of Compromise</h1>
          <p style={{color:"#94a3b8",margin:"4px 0"}}>Extracted from ClearSOC alerts and raw Wazuh telemetry</p>
          <small style={{color:"#64748b"}}>Last refresh: {lastRefresh || "Loading..."} | Showing {filtered.length} / {iocs.length}</small>
        </div>

        <button onClick={loadData} style={{display:"flex",alignItems:"center",gap:"8px",background:"rgba(14,165,233,0.16)",border:"1px solid rgba(56,189,248,0.4)",color:"#e0f2fe",borderRadius:"8px",padding:"10px 14px",fontWeight:700,cursor:"pointer"}}>
          <RefreshCw size={16}/> Refresh
        </button>
      </div>

      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:"14px",marginBottom:"16px"}}>
        <Kpi label="Total IOCs" value={iocs.length} color="#38bdf8" />
        <Kpi label="High Risk IOCs" value={highRisk} color="#ef4444" />
        <Kpi label="IPs" value={iocs.filter(i=>i.type==="IP").length} color="#f97316" />
        <Kpi label="Users / Hosts" value={iocs.filter(i=>["USER","HOST"].includes(i.type)).length} color="#a855f7" />
      </div>

      <div style={{display:"grid",gridTemplateColumns:"1fr 220px",gap:"12px",padding:"12px",background:"rgba(8,18,38,0.9)",border:"1px solid rgba(56,189,248,0.18)",borderRadius:"14px",marginBottom:"16px"}}>
        <div style={{display:"flex",alignItems:"center",gap:"10px",background:"#071426",border:"1px solid rgba(56,189,248,0.25)",borderRadius:"10px",padding:"10px 12px"}}>
          <Search size={16}/>
          <input
            value={search}
            onChange={(e)=>setSearch(e.target.value)}
            placeholder="Search IOC value, host, user, MITRE..."
            style={{width:"100%",background:"transparent",border:"none",outline:"none",color:"#e2e8f0"}}
          />
        </div>

        <select value={typeFilter} onChange={(e)=>setTypeFilter(e.target.value)}
          style={{background:"#071426",color:"#e2e8f0",border:"1px solid rgba(56,189,248,0.25)",borderRadius:"10px",padding:"10px"}}>
          {types.map(t => <option key={t} value={t}>{t === "ALL" ? "All Types" : t}</option>)}
        </select>
      </div>

      <div style={{background:"rgba(8,18,38,0.94)",border:"1px solid rgba(56,189,248,0.18)",borderRadius:"14px",overflow:"auto"}}>
        <table style={{width:"100%",borderCollapse:"collapse"}}>
          <thead>
            <tr>
              {["Type","Value","Count","Severity","Hosts","Users","MITRE","First Seen","Last Seen","Actions"].map(h => (
                <th key={h} style={{background:"rgba(15,23,42,0.95)",color:"#93c5fd",fontSize:"12px",textTransform:"uppercase",padding:"14px",textAlign:"left"}}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>

          <tbody>
            {loading ? (
              <tr><td colSpan="10" style={{padding:"45px",textAlign:"center",color:"#94a3b8"}}>Loading IOCs...</td></tr>
            ) : filtered.length === 0 ? (
              <tr><td colSpan="10" style={{padding:"45px",textAlign:"center",color:"#94a3b8"}}>No IOCs found</td></tr>
            ) : (
              filtered.slice(0,300).map((i, idx) => {
                const link = iocLink(i.type, i.value);

                return (
                  <tr key={idx}>
                    <td style={td}><Badge value={i.type} /></td>
                    <td style={{...td,fontFamily:"monospace",color:"#38bdf8",fontWeight:700,maxWidth:"280px",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}} title={i.value}>{i.value}</td>
                    <td style={td}>{i.count}</td>
                    <td style={td}><Sev value={i.severity} /></td>
                    <td style={td}>{[...i.hosts].filter(Boolean).slice(0,3).join(", ") || "-"}</td>
                    <td style={td}>{[...i.users].filter(Boolean).slice(0,3).join(", ") || "-"}</td>
                    <td style={td}>{[...i.mitre].filter(Boolean).slice(0,3).join(", ") || "-"}</td>
                    <td style={{...td,fontSize:"12px",color:"#94a3b8"}}>{formatTime(i.firstSeen)}</td>
                    <td style={{...td,fontSize:"12px",color:"#94a3b8"}}>{formatTime(i.lastSeen)}</td>
                    <td style={td}>
                      <div style={{display:"flex",gap:"6px"}}>
                        <button onClick={()=>copyValue(i.value)} style={actionBtn}><Copy size={13}/></button>
                        {link && (
                          <a href={link} target="_blank" rel="noreferrer" style={actionBtn}>
                            <ExternalLink size={13}/>
                          </a>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      <div style={{marginTop:"14px",color:"#64748b",fontSize:"12px"}}>
        IOC data is extracted from observed alerts and raw telemetry. It does not automatically prove malicious activity.
      </div>
    </div>
  );
}

const td = {
  padding:"14px",
  borderTop:"1px solid rgba(148,163,184,0.12)",
  color:"#e2e8f0",
  verticalAlign:"top"
};

const actionBtn = {
  display:"inline-flex",
  alignItems:"center",
  justifyContent:"center",
  width:"30px",
  height:"30px",
  background:"rgba(14,165,233,0.16)",
  border:"1px solid rgba(56,189,248,0.35)",
  color:"#e0f2fe",
  borderRadius:"8px",
  cursor:"pointer",
  textDecoration:"none"
};

function Kpi({ label, value, color }) {
  return (
    <div style={{background:"rgba(8,18,38,0.94)",border:`1px solid ${color}33`,borderRadius:"14px",padding:"16px"}}>
      <p style={{margin:"0 0 8px",color:"#94a3b8",fontSize:"12px",textTransform:"uppercase"}}>{label}</p>
      <h2 style={{margin:0,fontSize:"30px",color}}>{value}</h2>
    </div>
  );
}

function Badge({ value }) {
  return (
    <span style={{padding:"5px 10px",borderRadius:"999px",fontSize:"11px",fontWeight:800,color:"#38bdf8",border:"1px solid rgba(56,189,248,0.4)"}}>
      {value}
    </span>
  );
}

function Sev({ value }) {
  const v = String(value || "INFO").toUpperCase();
  const color = v === "CRITICAL" ? "#ef4444" : v === "HIGH" ? "#f97316" : v === "MEDIUM" ? "#eab308" : "#22c55e";

  return (
    <span style={{padding:"5px 10px",borderRadius:"999px",fontSize:"11px",fontWeight:800,color,border:`1px solid ${color}`}}>
      {v}
    </span>
  );
}
