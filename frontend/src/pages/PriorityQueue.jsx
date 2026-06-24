import { useEffect, useMemo, useState } from "react";
import { Search, RefreshCw, Eye, ShieldAlert, Activity, Flame } from "lucide-react";
import { useNavigate } from "react-router-dom";

const API_BASE = "http://localhost:8001";

function scoreItem(item) {
  const sev = String(item.severity || "INFO").toUpperCase();
  const phase = String(item.kill_chain_phase || "").toLowerCase();
  const mitre = (item.mitre || []).join(",").toLowerCase();

  let score = 0;

  if (sev === "CRITICAL") score += 50;
  else if (sev === "HIGH") score += 35;
  else if (sev === "MEDIUM") score += 20;
  else score += 5;

  if (phase.includes("privilege")) score += 25;
  if (mitre.includes("t1059")) score += 20;
  if (mitre.includes("t1550")) score += 35;
  if (phase.includes("lateral")) score += 35;
  if (mitre.includes("t1110")) score += 25;
  if (phase.includes("initial access")) score += 10;

  return Math.min(score, 100);
}

function decision(score, severity) {
  if (severity === "CRITICAL" || score >= 85) return "ESCALATE";
  if (score >= 50) return "INVESTIGATE";
  if (score >= 25) return "MONITOR";
  return "CLEAR";
}

function confidenceLabel(score) {
  if (score >= 75) return "HIGH";
  if (score >= 40) return "MEDIUM";
  return "LOW";
}

function parseTime(value) {
  const d = new Date(value);
  return isNaN(d.getTime()) ? null : d;
}

function formatTime(value) {
  const d = parseTime(value);
  if (!d) return "N/A";
  return d.toLocaleString();
}

export default function PriorityQueue() {
  const navigate = useNavigate();

  const [allItems, setAllItems] = useState([]);
  const [search, setSearch] = useState("");
  const [decisionFilter, setDecisionFilter] = useState("ACTIONABLE");
  const [lastRefresh, setLastRefresh] = useState("");
  const [loading, setLoading] = useState(true);

  async function loadQueue() {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/incidents`);
      const data = await res.json();
      setAllItems(Array.isArray(data) ? data : []);
      setLastRefresh(new Date().toLocaleTimeString());
    } catch (e) {
      console.error("Failed to load priority queue:", e);
      setAllItems([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadQueue();
  }, []);

  const scored = useMemo(() => {
    return allItems.map((item) => {
      const sev = String(item.severity || "INFO").toUpperCase();
      const score = scoreItem(item);
      const dec = decision(score, sev);

      return {
        item,
        score,
        severity: sev,
        confidence: confidenceLabel(score),
        decision: dec,
      };
    }).sort((a, b) => b.score - a.score);
  }, [allItems]);

  const escalateCount = scored.filter(r => r.decision === "ESCALATE").length;
  const investigateCount = scored.filter(r => r.decision === "INVESTIGATE").length;
  const monitorCount = scored.filter(r => r.decision === "MONITOR").length;

  const queue = useMemo(() => {
    const q = search.toLowerCase().trim();

    return scored.filter((row) => {
      const a = row.item;

      const matchSearch =
        !q ||
        String(a.host || "").toLowerCase().includes(q) ||
        String(a.user || "").toLowerCase().includes(q) ||
        String(a.title || "").toLowerCase().includes(q) ||
        String(a.summary || "").toLowerCase().includes(q) ||
        String(a.event_id || "").toLowerCase().includes(q) ||
        String(a.kill_chain_phase || "").toLowerCase().includes(q);

      let matchDecision = true;
      if (decisionFilter === "ACTIONABLE") {
        matchDecision = row.decision === "ESCALATE" || row.decision === "INVESTIGATE";
      } else if (decisionFilter !== "ALL") {
        matchDecision = row.decision === decisionFilter;
      }

      return matchSearch && matchDecision;
    });
  }, [scored, search, decisionFilter]);

  function openInvestigation(row) {
    localStorage.setItem("clearsoc_selected_alert", JSON.stringify(row.item));
    navigate("/investigation");
  }

  return (
    <div className="page pq-page">
      <div className="pq-header">
        <div>
          <h1>Priority Queue</h1>
          <p>Today's actionable work, ranked by risk score</p>
          <small>Last refresh: {lastRefresh || "Loading..."} | Showing: {queue.length} actionable item{queue.length === 1 ? "" : "s"} (of {allItems.length} total alerts)</small>
        </div>

        <button className="toolbar-btn" onClick={loadQueue}>
          <RefreshCw size={16} /> Refresh
        </button>
      </div>

      <div className="pq-kpi-grid">
        <div className="pq-kpi red"><Flame size={22} /><p>Escalate Now</p><h2>{escalateCount}</h2></div>
        <div className="pq-kpi orange"><ShieldAlert size={22} /><p>Investigate</p><h2>{investigateCount}</h2></div>
        <div className="pq-kpi yellow"><Eye size={22} /><p>Monitoring (not shown)</p><h2>{monitorCount}</h2></div>
        <div className="pq-kpi blue"><Activity size={22} /><p>Total Alerts</p><h2>{allItems.length}</h2></div>
      </div>

      <div className="pq-filter-bar">
        <div className="pq-search">
          <Search size={16} />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search host, user, event ID, kill chain phase, summary..."
          />
        </div>

        <select value={decisionFilter} onChange={(e) => setDecisionFilter(e.target.value)}>
          <option value="ACTIONABLE">Actionable (Escalate + Investigate)</option>
          <option value="ESCALATE">Escalate Only</option>
          <option value="INVESTIGATE">Investigate Only</option>
          <option value="ALL">Show Everything (30)</option>
        </select>
      </div>

      {!loading && queue.length === 0 && decisionFilter === "ACTIONABLE" && (
        <div style={{
          background: "rgba(34,197,94,0.08)", border: "1px solid rgba(34,197,94,0.2)",
          borderRadius: "8px", padding: "16px", marginBottom: "16px", color: "#22c55e",
          fontSize: "13px", fontWeight: 600
        }}>
          Nothing currently needs escalation or investigation. Switch the filter above to review monitored items.
        </div>
      )}

      <div className="pq-table-card">
        <table className="pq-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Risk</th>
              <th>Host</th>
              <th>User</th>
              <th>Kill Chain Phase</th>
              <th>Summary</th>
              <th>Time</th>
              <th>Severity</th>
              <th>Confidence</th>
              <th>Decision</th>
              <th>Action</th>
            </tr>
          </thead>

          <tbody>
            {loading ? (
              <tr><td colSpan="11" className="pq-empty">Loading priority queue...</td></tr>
            ) : queue.length === 0 ? (
              <tr><td colSpan="11" className="pq-empty">No items match this filter</td></tr>
            ) : (
              queue.slice(0, 200).map((row, idx) => {
                const a = row.item;

                return (
                  <tr key={a.investigation_id || idx}>
                    <td>{idx + 1}</td>
                    <td><span className={`pq-score ${row.score >= 75 ? "hot" : row.score >= 45 ? "warm" : "cool"}`}>{row.score}</span></td>
                    <td>{a.host || "-"}</td>
                    <td>{String(a.user || "-").split("\\").pop()}</td>
                    <td>{a.kill_chain_phase || "-"}</td>
                    <td className="pq-summary">{a.title || a.summary || "N/A"}</td>
                    <td className="pq-time">{formatTime(a.time)}</td>
                    <td><span className={`pq-badge sev-${row.severity.toLowerCase()}`}>{row.severity}</span></td>
                    <td><span className={`pq-badge conf-${row.confidence.toLowerCase()}`}>{row.confidence}</span></td>
                    <td><span className={`pq-badge dec-${row.decision.toLowerCase()}`}>{row.decision}</span></td>
                    <td>
                      <button className="pq-action-btn" onClick={() => openInvestigation(row)}>
                        <Eye size={13} /> Investigate
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
