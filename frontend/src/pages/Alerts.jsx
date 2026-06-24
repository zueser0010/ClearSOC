import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { RefreshCw, Search } from "lucide-react";
import { useGlobalTime } from "../utils/TimeContext";

const API_BASE = "http://localhost:8001";

const SEV_COLOR = {
  CRITICAL: "#ef4444", HIGH: "#f97316",
  MEDIUM: "#eab308", LOW: "#22c55e", INFO: "#3b82f6"
};

function parseTime(t) {
  const d = new Date(t);
  return isNaN(d.getTime()) ? null : d;
}

function formatDateTime(t) {
  const d = parseTime(t);
  if (!d) return "N/A";
  return d.toLocaleString("en-SG", {
    month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    hour12: false
  });
}

export default function Alerts() {
  const navigate = useNavigate();
  const { globalTime } = useGlobalTime();
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState("");
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("ALL");

  async function loadAlerts() {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE}/api/alerts`);
      const data = await response.json();
      setAlerts(Array.isArray(data) ? data : []);
      setLastRefresh(new Date().toLocaleTimeString());
    } catch (error) {
      setAlerts([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadAlerts(); }, []);

  const filteredAlerts = useMemo(() => {
    const now = new Date();
    const TIME_MS = { "1h":3600000,"6h":21600000,"24h":86400000,"7d":604800000,"30d":2592000000 };
    return alerts.filter((a) => {
      const sev = String(a.severity || "").toUpperCase();
      const q = search.toLowerCase();
      const matchesSearch = !q ||
        String(a.title || "").toLowerCase().includes(q) ||
        String(a.host || "").toLowerCase().includes(q) ||
        String(a.user || "").toLowerCase().includes(q) ||
        String(a.event_id || "").toLowerCase().includes(q) ||
        String(a.source_ip || "").toLowerCase().includes(q) ||
        String(a.pack || "").toLowerCase().includes(q) ||
        String(a.kill_chain_phase || "").toLowerCase().includes(q);
      const matchesSeverity = severity === "ALL" || sev === severity;
      let matchesTime = true;
      const alertTime = parseTime(a.time);
      if (globalTime !== "ALL" && alertTime && TIME_MS[globalTime]) {
        matchesTime = (now - alertTime) <= TIME_MS[globalTime];
      }
      return matchesSearch && matchesSeverity && matchesTime;
    });
  }, [alerts, search, severity, globalTime]);

  const counts = {
    total: filteredAlerts.length,
    critical: filteredAlerts.filter(a => a.severity === "CRITICAL").length,
    high: filteredAlerts.filter(a => a.severity === "HIGH").length,
    medium: filteredAlerts.filter(a => a.severity === "MEDIUM").length,
    low: filteredAlerts.filter(a => ["LOW","INFO"].includes(a.severity)).length,
  };

  return (
    <div className="page">
      {/* HEADER */}
      <div className="alerts-header">
        <div>
          <h1>Alerts</h1>
          <p style={{color:"#64748b",fontSize:"13px",margin:"4px 0 0"}}>SOC alerts requiring analyst review</p>
          <small style={{color:"#475569"}}>
            Last refresh: {lastRefresh || "Loading..."} | Showing: {filteredAlerts.length} / {alerts.length}
          </small>
        </div>
        <button className="toolbar-btn" onClick={loadAlerts}>
          <RefreshCw size={16}/> Refresh
        </button>
      </div>

      {/* KPI CARDS */}
      <div className="alert-kpi-grid">
        {[
          {label:"Total", val:counts.total, color:"#38bdf8"},
          {label:"Critical", val:counts.critical, color:"#ef4444"},
          {label:"High", val:counts.high, color:"#f97316"},
          {label:"Medium", val:counts.medium, color:"#eab308"},
          {label:"Low/Info", val:counts.low, color:"#22c55e"},
        ].map(k => (
          <div key={k.label} className="alert-kpi" style={{borderColor:`${k.color}33`}}>
            <div>
              <p style={{color:"#64748b",fontSize:"12px",margin:0}}>{k.label}</p>
              <h2 style={{color:k.color,fontSize:"28px",fontWeight:700,margin:"4px 0 0"}}>{k.val}</h2>
            </div>
          </div>
        ))}
      </div>

      {/* FILTERS */}
      <div style={{display:"flex",gap:"12px",marginBottom:"16px",flexWrap:"wrap",alignItems:"center"}}>
        <div className="search-box" style={{flex:1,minWidth:"200px"}}>
          <Search size={16} color="#475569"/>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search title, host, user, event ID, kill chain phase..."
          />
        </div>
        <div style={{display:"flex",gap:"6px",flexWrap:"wrap"}}>
          {[
            {v:"ALL",color:"#64748b"},
            {v:"CRITICAL",color:"#ef4444"},
            {v:"HIGH",color:"#f97316"},
            {v:"MEDIUM",color:"#eab308"},
            {v:"LOW",color:"#22c55e"},
          ].map(s => (
            <button key={s.v} onClick={() => setSeverity(s.v)}
              style={{
                background: severity===s.v ? `${s.color}22` : "rgba(255,255,255,0.03)",
                border: `1px solid ${severity===s.v ? s.color : "rgba(255,255,255,0.08)"}`,
                color: severity===s.v ? s.color : "#475569",
                padding:"7px 14px", borderRadius:"8px", cursor:"pointer",
                fontSize:"12px", fontWeight:600
              }}>
              {s.v}
            </button>
          ))}
        </div>
      </div>

      {/* TABLE */}
      <div className="alerts-table-card">
        <table className="alerts-table">
          <thead>
            <tr>
              <th>Date & Time</th>
              <th>Host</th>
              <th>User</th>
              <th>Title</th>
              <th>Kill Chain</th>
              <th>Event ID</th>
              <th>MITRE</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan="10" style={{textAlign:"center",padding:"40px",color:"#475569"}}>Loading alerts...</td></tr>
            ) : filteredAlerts.length === 0 ? (
              <tr><td colSpan="10" style={{textAlign:"center",padding:"40px",color:"#475569"}}>No alerts found</td></tr>
            ) : filteredAlerts.slice(0,200).map((alert, idx) => {
              const sevColor = SEV_COLOR[alert.severity] || "#94a3b8";
              return (
                <tr key={idx} style={{borderLeft:`3px solid ${sevColor}22`}}>
                  <td style={{fontFamily:"monospace",fontSize:"12px",color:"#94a3b8",whiteSpace:"nowrap"}}>
                    {formatDateTime(alert.time)}
                  </td>
                  <td style={{color:"#e2e8f0"}}>{alert.host}</td>
                  <td style={{color:"#94a3b8"}}>{alert.user?.split("\\").pop() || alert.user}</td>
                  <td style={{maxWidth:"220px",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{alert.title}</td>
                  <td>
                    {alert.kill_chain_phase && (
                      <span style={{background:"rgba(56,189,248,0.1)",color:"#38bdf8",padding:"2px 8px",borderRadius:"4px",fontSize:"11px",whiteSpace:"nowrap"}}>
                        {alert.kill_chain_phase}
                      </span>
                    )}
                  </td>
                  <td style={{fontFamily:"monospace",color:"#64748b"}}>{alert.event_id}</td>
                  <td style={{fontSize:"11px",color:"#7dd3fc"}}>
                    {(alert.mitre||[]).join(", ")}
                  </td>
                  <td>
                    <span style={{color:sevColor,fontWeight:700,fontSize:"12px"}}>{alert.severity}</span>
                  </td>
                  <td><span style={{color:"#22c55e",fontSize:"11px",fontWeight:600}}>● OPEN</span></td>
                  <td>
                    <button className="btn-primary" onClick={() => {
                      localStorage.setItem("clearsoc_selected_alert", JSON.stringify(alert));
                      navigate("/investigation");
                    }}>
                      <Search size={14}/> Investigate
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
