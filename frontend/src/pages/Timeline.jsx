import { useEffect, useState, useMemo } from "react";

const API = "http://localhost:8001";

const SEV_MAP = (level) => {
  const n = Number(level || 0);
  if (n >= 12) return { label:"CRITICAL", color:"#ef4444" };
  if (n >= 8)  return { label:"HIGH",     color:"#f97316" };
  if (n >= 5)  return { label:"MEDIUM",   color:"#eab308" };
  return { label:"INFO", color:"#3b82f6" };
};

export default function Timeline() {
  const [summary, setSummary] = useState([]);
  const [events, setEvents] = useState([]);
  const [selectedDate, setSelectedDate] = useState("");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState("ALL");
  const [mode, setMode] = useState("date"); // date or range

  useEffect(() => {
    fetch(`${API}/api/events-summary`)
      .then(r => r.json())
      .then(d => setSummary(Array.isArray(d) ? d : []))
      .catch(() => {});
  }, []);

  async function loadByDate(date) {
    if (!date) return;
    setLoading(true);
    try {
      const d = await fetch(`${API}/api/events-by-date?date=${date}&limit=500`).then(r => r.json());
      setEvents(Array.isArray(d) ? d : []);
    } catch(e) { setEvents([]); }
    finally { setLoading(false); }
  }

  async function loadByRange() {
    if (!startDate || !endDate) return;
    setLoading(true);
    try {
      const d = await fetch(`${API}/api/events-by-date?start=${startDate}&end=${endDate}&limit=500`).then(r => r.json());
      setEvents(Array.isArray(d) ? d : []);
    } catch(e) { setEvents([]); }
    finally { setLoading(false); }
  }

  const filtered = useMemo(() => {
    const q = search.toLowerCase().trim();
    return events.filter(e => {
      const matchSearch = !q ||
        (e.rule_description||"").toLowerCase().includes(q) ||
        (e.host||"").toLowerCase().includes(q) ||
        (e.user||"").toLowerCase().includes(q) ||
        (e.event_id||"").includes(q) ||
        (e.source_ip||"").includes(q);
      const level = Number(e.rule_level || 0);
      const sev = level>=12?"CRITICAL":level>=8?"HIGH":level>=5?"MEDIUM":level>=3?"LOW":"INFO";
      const matchSev = sevFilter === "ALL" || sev === sevFilter;
      return matchSearch && matchSev;
    });
  }, [events, search, sevFilter]);

  // Group by hour for timeline view
  const grouped = useMemo(() => {
    const g = {};
    filtered.forEach(e => {
      const t = new Date(e.timestamp);
      const hour = isNaN(t) ? "Unknown" : `${String(t.getHours()).padStart(2,"0")}:00`;
      if (!g[hour]) g[hour] = [];
      g[hour].push(e);
    });
    return Object.entries(g).sort((a,b) => a[0].localeCompare(b[0]));
  }, [filtered]);

  const maxEvents = Math.max(...summary.map(s => s.windows_events || 0), 1);

  return (
    <div style={{padding:"20px",color:"#e2e8f0"}}>

      {/* HEADER */}
      <div style={{marginBottom:"20px"}}>
        <h1 style={{fontSize:"24px",fontWeight:700,color:"white",margin:0}}>📅 Timeline</h1>
        <p style={{color:"#64748b",fontSize:"13px",margin:"4px 0 0"}}>Chronological view of security events by date</p>
      </div>

      {/* CALENDAR HEATMAP */}
      <div style={{background:"rgba(8,18,38,0.95)",border:"1px solid rgba(56,189,248,0.12)",borderRadius:"12px",padding:"20px",marginBottom:"16px"}}>
        <p style={{color:"#64748b",fontSize:"11px",fontWeight:600,textTransform:"uppercase",letterSpacing:"0.5px",margin:"0 0 14px"}}>
          Activity Heatmap — Click a date to investigate
        </p>
        <div style={{display:"flex",flexWrap:"wrap",gap:"6px"}}>
          {summary.map((s,i) => {
            const intensity = s.windows_events / maxEvents;
            const bg = s.windows_events === 0
              ? "rgba(255,255,255,0.03)"
              : intensity > 0.7 ? "rgba(239,68,68,0.7)"
              : intensity > 0.4 ? "rgba(249,115,22,0.6)"
              : intensity > 0.1 ? "rgba(234,179,8,0.5)"
              : "rgba(34,197,94,0.4)";
            const isSelected = selectedDate === s.date;
            return (
              <div key={i}
                onClick={() => { setSelectedDate(s.date); setMode("date"); loadByDate(s.date); }}
                title={`${s.date}: ${s.windows_events} Windows events, ${s.total} total`}
                style={{
                  width:"52px", height:"52px", borderRadius:"8px",
                  background: bg,
                  border: isSelected ? "2px solid #38bdf8" : "1px solid rgba(255,255,255,0.06)",
                  cursor:"pointer", display:"flex", flexDirection:"column",
                  alignItems:"center", justifyContent:"center", gap:"2px",
                  transition:"all 0.15s",
                  boxShadow: isSelected ? "0 0 12px rgba(56,189,248,0.4)" : "none"
                }}
              >
                <span style={{fontSize:"9px",color:"rgba(255,255,255,0.6)"}}>{s.date?.slice(5)}</span>
                <span style={{fontSize:"11px",fontWeight:700,color:"white"}}>{s.windows_events}</span>
              </div>
            );
          })}
        </div>
        <div style={{display:"flex",gap:"16px",marginTop:"12px",flexWrap:"wrap"}}>
          {[
            {color:"rgba(34,197,94,0.4)",label:"Low activity"},
            {color:"rgba(234,179,8,0.5)",label:"Medium"},
            {color:"rgba(249,115,22,0.6)",label:"High"},
            {color:"rgba(239,68,68,0.7)",label:"Critical"},
            {color:"rgba(255,255,255,0.03)",label:"No data"},
          ].map(l => (
            <div key={l.label} style={{display:"flex",alignItems:"center",gap:"6px"}}>
              <div style={{width:"12px",height:"12px",borderRadius:"3px",background:l.color,border:"1px solid rgba(255,255,255,0.1)"}}/>
              <span style={{fontSize:"11px",color:"#64748b"}}>{l.label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* FILTERS */}
      <div style={{background:"rgba(8,18,38,0.95)",border:"1px solid rgba(56,189,248,0.12)",borderRadius:"12px",padding:"16px",marginBottom:"16px"}}>
        <div style={{display:"flex",gap:"12px",flexWrap:"wrap",alignItems:"flex-end"}}>
          <div>
            <p style={{color:"#64748b",fontSize:"11px",margin:"0 0 6px",textTransform:"uppercase"}}>Mode</p>
            <div style={{display:"flex",gap:"8px"}}>
              {["date","range"].map(m => (
                <button key={m} onClick={() => setMode(m)}
                  style={{background: mode===m ? "rgba(56,189,248,0.15)" : "rgba(255,255,255,0.03)", border:`1px solid ${mode===m?"#38bdf8":"rgba(255,255,255,0.08)"}`, color: mode===m?"#38bdf8":"#64748b", padding:"6px 14px", borderRadius:"6px", cursor:"pointer", fontSize:"12px", textTransform:"capitalize"}}>
                  {m === "date" ? "Specific Date" : "Date Range"}
                </button>
              ))}
            </div>
          </div>

          {mode === "date" ? (
            <div>
              <p style={{color:"#64748b",fontSize:"11px",margin:"0 0 6px",textTransform:"uppercase"}}>Select Date</p>
              <input type="date" value={selectedDate}
                onChange={e => { setSelectedDate(e.target.value); loadByDate(e.target.value); }}
                style={{background:"rgba(255,255,255,0.05)",border:"1px solid rgba(255,255,255,0.1)",color:"#e2e8f0",padding:"8px 12px",borderRadius:"8px",fontSize:"13px"}}
              />
            </div>
          ) : (
            <>
              <div>
                <p style={{color:"#64748b",fontSize:"11px",margin:"0 0 6px",textTransform:"uppercase"}}>Start Date</p>
                <input type="date" value={startDate} onChange={e => setStartDate(e.target.value)}
                  style={{background:"rgba(255,255,255,0.05)",border:"1px solid rgba(255,255,255,0.1)",color:"#e2e8f0",padding:"8px 12px",borderRadius:"8px",fontSize:"13px"}}
                />
              </div>
              <div>
                <p style={{color:"#64748b",fontSize:"11px",margin:"0 0 6px",textTransform:"uppercase"}}>End Date</p>
                <input type="date" value={endDate} onChange={e => setEndDate(e.target.value)}
                  style={{background:"rgba(255,255,255,0.05)",border:"1px solid rgba(255,255,255,0.1)",color:"#e2e8f0",padding:"8px 12px",borderRadius:"8px",fontSize:"13px"}}
                />
              </div>
              <button onClick={loadByRange}
                style={{background:"rgba(56,189,248,0.1)",border:"1px solid rgba(56,189,248,0.3)",color:"#38bdf8",padding:"8px 16px",borderRadius:"8px",cursor:"pointer",fontSize:"13px",fontWeight:600}}>
                Load Range
              </button>
            </>
          )}

          <div style={{flex:1,minWidth:"200px"}}>
            <p style={{color:"#64748b",fontSize:"11px",margin:"0 0 6px",textTransform:"uppercase"}}>Search Events</p>
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search rule, host, user, event ID..."
              style={{width:"100%",background:"rgba(255,255,255,0.05)",border:"1px solid rgba(255,255,255,0.1)",color:"#e2e8f0",padding:"8px 12px",borderRadius:"8px",fontSize:"13px",boxSizing:"border-box"}}
            />
          </div>
          <div>
            <p style={{color:"#64748b",fontSize:"11px",margin:"0 0 6px",textTransform:"uppercase"}}>Severity</p>
            <div style={{display:"flex",gap:"6px"}}>
              {[
                {label:"ALL",color:"#64748b"},
                {label:"CRITICAL",color:"#ef4444"},
                {label:"HIGH",color:"#f97316"},
                {label:"MEDIUM",color:"#eab308"},
                {label:"LOW",color:"#22c55e"},
                {label:"INFO",color:"#3b82f6"},
              ].map(s => (
                <button key={s.label} onClick={() => setSevFilter(s.label)}
                  style={{background: sevFilter===s.label ? `${s.color}22` : "rgba(255,255,255,0.03)",
                    border:`1px solid ${sevFilter===s.label ? s.color : "rgba(255,255,255,0.08)"}`,
                    color: sevFilter===s.label ? s.color : "#475569",
                    padding:"6px 10px",borderRadius:"6px",cursor:"pointer",fontSize:"11px",fontWeight:600}}>
                  {s.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* STATS */}
      {events.length > 0 && (
        <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:"10px",marginBottom:"16px"}}>
          {[
            {label:"Total Events", value:filtered.length, color:"#38bdf8"},
            {label:"High/Critical", value:filtered.filter(e=>Number(e.rule_level)>=8).length, color:"#ef4444"},
            {label:"Unique Hosts", value:[...new Set(filtered.map(e=>e.host).filter(Boolean))].length, color:"#f97316"},
            {label:"Unique Users", value:[...new Set(filtered.map(e=>e.user).filter(Boolean))].length, color:"#a855f7"},
          ].map(s => (
            <div key={s.label} style={{background:"rgba(8,18,38,0.95)",border:"1px solid rgba(56,189,248,0.1)",borderRadius:"10px",padding:"14px",textAlign:"center"}}>
              <p style={{color:"#64748b",fontSize:"11px",margin:"0 0 4px",textTransform:"uppercase"}}>{s.label}</p>
              <p style={{color:s.color,fontSize:"24px",fontWeight:700,margin:0}}>{s.value}</p>
            </div>
          ))}
        </div>
      )}

      {/* TIMELINE */}
      {loading ? (
        <div style={{textAlign:"center",padding:"40px",color:"#475569"}}>Loading events...</div>
      ) : events.length === 0 ? (
        <div style={{background:"rgba(8,18,38,0.95)",border:"1px solid rgba(56,189,248,0.1)",borderRadius:"12px",padding:"40px",textAlign:"center"}}>
          <p style={{color:"#475569",fontSize:"14px"}}>Select a date from the heatmap or use the date picker above</p>
        </div>
      ) : (
        <div style={{display:"flex",flexDirection:"column",gap:"12px"}}>
          {grouped.map(([hour, evts]) => (
            <div key={hour} style={{background:"rgba(8,18,38,0.95)",border:"1px solid rgba(56,189,248,0.1)",borderRadius:"12px",overflow:"hidden"}}>
              <div style={{background:"rgba(56,189,248,0.06)",borderBottom:"1px solid rgba(56,189,248,0.1)",padding:"10px 16px",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                <span style={{color:"#38bdf8",fontWeight:700,fontSize:"13px",fontFamily:"monospace"}}>
                  🕐 {selectedDate || startDate} {hour}
                </span>
                <span style={{color:"#475569",fontSize:"12px"}}>{evts.length} events</span>
              </div>
              <table style={{width:"100%",borderCollapse:"collapse",fontSize:"12px"}}>
                <thead>
                  <tr>
                    {["Time","Host","User","Event ID","Level","Description"].map(h => (
                      <th key={h} style={{color:"#475569",fontWeight:600,padding:"8px 12px",textAlign:"left",borderBottom:"1px solid rgba(255,255,255,0.04)",fontSize:"10px",textTransform:"uppercase"}}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {evts.map((e,i) => {
                    const sev = SEV_MAP(e.rule_level);
                    return (
                      <tr key={i} style={{borderBottom:"1px solid rgba(255,255,255,0.03)"}}>
                        <td style={{padding:"8px 12px",fontFamily:"monospace",color:"#e2e8f0",fontSize:"13px",fontWeight:600}}>{e.timestamp?.split("T")[1]?.split("+")[0]?.slice(0,8) || "--:--:--"}</td>
                        <td style={{padding:"8px 12px",color:"#e2e8f0"}}>{e.host}</td>
                        <td style={{padding:"8px 12px",color:"#94a3b8"}}>{e.user||"-"}</td>
                        <td style={{padding:"8px 12px",color:"#38bdf8",fontFamily:"monospace"}}>{e.event_id||"-"}</td>
                        <td style={{padding:"8px 12px"}}>
                          <span style={{color:sev.color,fontWeight:700,fontSize:"11px"}}>{sev.label}</span>
                        </td>
                        <td style={{padding:"8px 12px",color:"#64748b",maxWidth:"300px",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{e.rule_description}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
