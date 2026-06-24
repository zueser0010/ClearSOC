import { useEffect, useMemo, useState } from "react";
import { Search, RefreshCw, ShieldAlert, Clock, Server, User, Target } from "lucide-react";

const API_BASE = "http://localhost:8001";

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

export default function Incidents() {
  const [items, setItems] = useState([]);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [open, setOpen] = useState(null);
  const [lastRefresh, setLastRefresh] = useState("");

  async function loadData() {
    try {
      const res = await fetch(`${API_BASE}/api/incidents`);
      const data = await res.json();
      setItems(Array.isArray(data) ? data : []);
      setLastRefresh(new Date().toLocaleString());
    } catch {
      setItems([]);
    }
  }

  useEffect(() => {
    loadData();
  }, []);

  const incidents = useMemo(() => {
    return items.map((i, idx) => {
      const first = i.timeline?.[0]?.time || i.failed_login_bursts?.[0]?.start_time || "";
      const last = i.timeline?.[i.timeline.length - 1]?.time || i.failed_login_bursts?.[0]?.end_time || first;

      return {
        id: i.incident_id || `INC-${String(idx + 1).padStart(5, "0")}`,
        title: i.chain_type || i.module || "Security Incident",
        host: i.host || i.destination_host || "N/A",
        user: i.user || "N/A",
        source_ip: i.source_ip || "N/A",
        severity: i.severity || "LOW",
        confidence: i.correlation_confidence || i.confidence || "LOW",
        risk_score: i.risk_score || 0,
        first,
        last,
        alert_count: i.alert_count || i.failed_login_count || i.timeline?.length || 1,
        mitre: Array.isArray(i.mitre) ? i.mitre : [],
        reasons: i.reasons || [],
        summary: i.kill_chain_summary || i.summary || "No summary available",
        actions: i.recommended_actions || [],
        timeline: i.timeline || [],
        raw: i
      };
    });
  }, [items]);

  const filtered = incidents.filter(i => {
    const q = search.toLowerCase().trim();

    const matchSearch =
      !q ||
      i.id.toLowerCase().includes(q) ||
      i.title.toLowerCase().includes(q) ||
      i.host.toLowerCase().includes(q) ||
      i.user.toLowerCase().includes(q) ||
      i.source_ip.toLowerCase().includes(q) ||
      i.summary.toLowerCase().includes(q) ||
      i.mitre.join(" ").toLowerCase().includes(q);

    const matchSeverity =
      severity === "ALL" || String(i.severity).toUpperCase() === severity;

    return matchSearch && matchSeverity;
  });

  const high = incidents.filter(i => ["HIGH", "CRITICAL"].includes(String(i.severity).toUpperCase())).length;
  const medium = incidents.filter(i => String(i.severity).toUpperCase() === "MEDIUM").length;
  const openCount = incidents.length;
  const avgRisk = incidents.length ? Math.round(incidents.reduce((a,b)=>a + Number(b.risk_score || 0),0) / incidents.length) : 0;

  return (
    <div className="page" style={{padding:"24px",color:"#e2e8f0"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:"18px"}}>
        <div>
          <h1 style={{fontSize:"32px",margin:0,color:"#f8fafc"}}>Incidents</h1>
          <p style={{color:"#94a3b8",margin:"4px 0"}}>Correlated investigation cases built from alerts and attack chains</p>
          <small style={{color:"#64748b"}}>Last refresh: {lastRefresh || "Loading..."} | Showing {filtered.length} / {incidents.length}</small>
        </div>

        <button onClick={loadData} style={btnStyle}>
          <RefreshCw size={16}/> Refresh
        </button>
      </div>

      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:"14px",marginBottom:"16px"}}>
        <Kpi label="Open Incidents" value={openCount} color="#38bdf8" />
        <Kpi label="High / Critical" value={high} color="#ef4444" />
        <Kpi label="Medium" value={medium} color="#eab308" />
        <Kpi label="Avg Risk Score" value={avgRisk} color="#a855f7" />
      </div>

      <div style={{display:"grid",gridTemplateColumns:"1fr 220px",gap:"12px",padding:"12px",background:"rgba(8,18,38,0.9)",border:"1px solid rgba(56,189,248,0.18)",borderRadius:"14px",marginBottom:"16px"}}>
        <div style={{display:"flex",alignItems:"center",gap:"10px",background:"#071426",border:"1px solid rgba(56,189,248,0.25)",borderRadius:"10px",padding:"10px 12px"}}>
          <Search size={16}/>
          <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search incident, host, user, IP, MITRE..."
            style={{width:"100%",background:"transparent",border:"none",outline:"none",color:"#e2e8f0"}} />
        </div>

        <select value={severity} onChange={e=>setSeverity(e.target.value)}
          style={{background:"#071426",color:"#e2e8f0",border:"1px solid rgba(56,189,248,0.25)",borderRadius:"10px",padding:"10px"}}>
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
      </div>

      <div style={{display:"grid",gap:"14px"}}>
        {filtered.length === 0 ? (
          <div style={{padding:"45px",textAlign:"center",color:"#94a3b8",background:"rgba(8,18,38,0.94)",border:"1px solid rgba(56,189,248,0.18)",borderRadius:"14px"}}>
            No incidents found
          </div>
        ) : filtered.map((i, idx) => {
          const color = sevColor(i.severity);
          const expanded = open === idx;

          return (
            <div key={idx} style={{background:"rgba(8,18,38,0.94)",border:`1px solid ${color}33`,borderRadius:"14px",overflow:"hidden"}}>
              <div onClick={()=>setOpen(expanded ? null : idx)} style={{padding:"18px",cursor:"pointer"}}>
                <div style={{display:"flex",justifyContent:"space-between",gap:"14px",alignItems:"flex-start"}}>
                  <div>
                    <div style={{display:"flex",alignItems:"center",gap:"10px",marginBottom:"8px"}}>
                      <ShieldAlert size={18} color={color}/>
                      <h3 style={{margin:0,color:"#f8fafc",fontSize:"17px"}}>{i.title}</h3>
                      <Badge value={i.severity} color={color}/>
                      <Badge value={i.confidence} color="#38bdf8"/>
                    </div>

                    <p style={{margin:"0 0 10px",color:"#94a3b8",fontSize:"13px",lineHeight:"1.5"}}>{i.summary}</p>

                    <div style={{display:"flex",gap:"14px",flexWrap:"wrap",fontSize:"12px",color:"#cbd5e1"}}>
                      <span><Server size={13}/> Host: <b>{i.host}</b></span>
                      <span><User size={13}/> User: <b>{i.user}</b></span>
                      <span><Target size={13}/> Source: <b>{i.source_ip}</b></span>
                      <span><Clock size={13}/> {fmt(i.first)} → {fmt(i.last)}</span>
                    </div>
                  </div>

                  <div style={{textAlign:"right",minWidth:"120px"}}>
                    <div style={{fontSize:"30px",fontWeight:800,color}}>{i.risk_score}</div>
                    <div style={{fontSize:"11px",color:"#64748b"}}>risk score</div>
                    <div style={{marginTop:"8px",fontSize:"12px",color:"#94a3b8"}}>{i.alert_count} related alerts</div>
                  </div>
                </div>
              </div>

              {expanded && (
                <div style={{borderTop:"1px solid rgba(148,163,184,0.12)",padding:"18px"}}>
                  <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:"14px",marginBottom:"14px"}}>
                    <Panel title="Why This Became an Incident" color="#38bdf8">
                      {(i.reasons.length ? i.reasons : ["Security alerts were correlated into this incident."]).map((r,n)=>(
                        <li key={n}>{r}</li>
                      ))}
                    </Panel>

                    <Panel title="Recommended Analyst Actions" color="#22c55e">
                      {(i.actions.length ? i.actions : ["Review related alerts", "Validate user and source IP", "Decide FP / Monitor / Escalate"]).map((a,n)=>(
                        <li key={n}>{a}</li>
                      ))}
                    </Panel>
                  </div>

                  <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:"10px",marginBottom:"14px"}}>
                    <Mini label="MITRE" value={i.mitre.join(", ") || "N/A"} />
                    <Mini label="First Seen" value={fmt(i.first)} />
                    <Mini label="Last Seen" value={fmt(i.last)} />
                  </div>

                  <div style={{background:"rgba(255,255,255,0.03)",border:"1px solid rgba(255,255,255,0.07)",borderRadius:"10px",padding:"14px"}}>
                    <p style={{color:"#eab308",fontSize:"12px",fontWeight:800,margin:"0 0 10px"}}>Incident Timeline</p>
                    {i.timeline.length === 0 ? (
                      <p style={{color:"#64748b",margin:0}}>No timeline available</p>
                    ) : i.timeline.map((t,n)=>(
                      <div key={n} style={{borderLeft:"2px solid #38bdf8",paddingLeft:"12px",marginBottom:"10px"}}>
                        <p style={{margin:"0 0 4px",color:"#e2e8f0",fontWeight:700,fontSize:"13px"}}>{t.stage || "Event"} — {t.event || t.event_id}</p>
                        <p style={{margin:"0 0 3px",color:"#94a3b8",fontSize:"12px"}}>{fmt(t.time)} | Host: {t.host || "N/A"} | User: {t.user || "N/A"} | Source: {t.source_ip || "N/A"}</p>
                        <p style={{margin:0,color:"#64748b",fontSize:"12px"}}>{t.details || t.summary || ""}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

const btnStyle = {
  display:"flex",
  alignItems:"center",
  gap:"8px",
  background:"rgba(14,165,233,0.16)",
  border:"1px solid rgba(56,189,248,0.4)",
  color:"#e0f2fe",
  borderRadius:"8px",
  padding:"10px 14px",
  fontWeight:700,
  cursor:"pointer"
};

function Kpi({ label, value, color }) {
  return (
    <div style={{background:"rgba(8,18,38,0.94)",border:`1px solid ${color}33`,borderRadius:"14px",padding:"16px"}}>
      <p style={{margin:"0 0 8px",color:"#94a3b8",fontSize:"12px",textTransform:"uppercase"}}>{label}</p>
      <h2 style={{margin:0,fontSize:"30px",color}}>{value}</h2>
    </div>
  );
}

function Badge({ value, color }) {
  return (
    <span style={{padding:"4px 9px",borderRadius:"999px",fontSize:"10px",fontWeight:800,color,border:`1px solid ${color}`}}>
      {value}
    </span>
  );
}

function Panel({ title, color, children }) {
  return (
    <div style={{background:"rgba(255,255,255,0.03)",border:`1px solid ${color}33`,borderRadius:"10px",padding:"14px"}}>
      <p style={{color,fontSize:"12px",fontWeight:800,margin:"0 0 8px"}}>{title}</p>
      <ul style={{margin:0,paddingLeft:"18px",display:"grid",gap:"6px",color:"#cbd5e1",fontSize:"12px"}}>
        {children}
      </ul>
    </div>
  );
}

function Mini({ label, value }) {
  return (
    <div style={{background:"rgba(255,255,255,0.03)",border:"1px solid rgba(255,255,255,0.07)",borderRadius:"8px",padding:"10px"}}>
      <p style={{margin:"0 0 5px",color:"#64748b",fontSize:"10px",textTransform:"uppercase"}}>{label}</p>
      <p style={{margin:0,color:"#e2e8f0",fontSize:"12px",fontWeight:800}}>{value}</p>
    </div>
  );
}
