import { useEffect, useMemo, useState } from "react";
import { Search, RefreshCw, Eye, Server, User, AlertTriangle } from "lucide-react";
import { useNavigate } from "react-router-dom";
import "./Discover.css";

const API_BASE = "http://localhost:8001";

function mapSeverity(level) {
  const n = Number(level || 0);
  if (n >= 12) return "CRITICAL";
  if (n >= 8) return "HIGH";
  if (n >= 5) return "MEDIUM";
  return "INFO";
}

function parseDate(value) {
  const d = new Date(value);
  return isNaN(d.getTime()) ? null : d;
}

function formatTime(value) {
  const d = parseDate(value);
  if (!d) return "N/A";
  return d.toLocaleString();
}

export default function Discover() {
  const navigate = useNavigate();

  const [logs, setLogs] = useState([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [hostFilter, setHostFilter] = useState("ALL");
  const [eventFilter, setEventFilter] = useState("ALL");
  const [timeFilter, setTimeFilter] = useState("ALL");
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState("");

  async function loadData() {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/raw-logs?limit=1000`);
      const data = await res.json();
      setLogs(Array.isArray(data) ? data : (data.logs || []));
      setLastRefresh(new Date().toLocaleTimeString());
    } catch (err) {
      console.error("Failed to load Discover logs:", err);
      setLogs([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  }, []);

  const hosts = useMemo(() => {
    return [...new Set(logs.map(l => l.host).filter(Boolean))].sort();
  }, [logs]);

  const eventIds = useMemo(() => {
    return [...new Set(logs.map(l => l.event_id).filter(Boolean))].sort();
  }, [logs]);

  const filteredLogs = useMemo(() => {
    const now = new Date();
    const term = searchTerm.toLowerCase().trim();

    return logs.filter((log) => {
      const sev = mapSeverity(log.rule_level);
      const timestamp = parseDate(log.timestamp);

      const matchesSearch =
        !term ||
        String(log.rule_description || "").toLowerCase().includes(term) ||
        String(log.host || "").toLowerCase().includes(term) ||
        String(log.user || "").toLowerCase().includes(term) ||
        String(log.event_id || "").toLowerCase().includes(term) ||
        String(log.source_ip || "").toLowerCase().includes(term) ||
        String(log.process || "").toLowerCase().includes(term) ||
        String(log.command_line || "").toLowerCase().includes(term);

      const matchesSeverity =
        severityFilter === "ALL" || sev === severityFilter;

      const matchesHost =
        hostFilter === "ALL" || log.host === hostFilter;

      const matchesEvent =
        eventFilter === "ALL" || log.event_id === eventFilter;

      let matchesTime = true;
      if (timeFilter !== "ALL" && timestamp) {
        const ageMs = now - timestamp;
        if (timeFilter === "1H") matchesTime = ageMs <= 60 * 60 * 1000;
        if (timeFilter === "24H") matchesTime = ageMs <= 24 * 60 * 60 * 1000;
        if (timeFilter === "7D") matchesTime = ageMs <= 7 * 24 * 60 * 60 * 1000;
        if (timeFilter === "30D") matchesTime = ageMs <= 30 * 24 * 60 * 60 * 1000;
      }

      return matchesSearch && matchesSeverity && matchesHost && matchesEvent && matchesTime;
    });
  }, [logs, searchTerm, severityFilter, hostFilter, eventFilter, timeFilter]);

  const highCritical = filteredLogs.filter(l => ["HIGH", "CRITICAL"].includes(mapSeverity(l.rule_level))).length;
  const uniqueHosts = new Set(filteredLogs.map(l => l.host).filter(Boolean)).size;

  function investigate(log) {
    const alertLike = {
      alert_id: `DISC-${log.id || Date.now()}`,
      time: log.timestamp,
      host: log.host,
      user: log.user,
      source_ip: log.source_ip || "unknown",
      destination_ip: log.destination_ip || "unknown",
      event_id: log.event_id,
      process: log.process,
      parent_process: log.parent_process,
      command_line: log.command_line,
      title: log.rule_description || "Raw Wazuh Event",
      summary: log.rule_description || log.command_line || "Raw event selected from Discover",
      severity: mapSeverity(log.rule_level),
      status: "OPEN",
      raw: log.raw || log,
    };

    localStorage.setItem("clearsoc_selected_alert", JSON.stringify(alertLike));
    navigate("/investigation");
  }

  return (
    <div className="discover-page">
      <div className="discover-header">
        <h1 className="discover-title">Threat Discovery</h1>
        <p className="discover-subtitle">Raw Wazuh-style telemetry from parser output</p>

        <div className="discover-toolbar">
          <span className="discover-stats">
            Last refresh: {lastRefresh || "Loading..."} | Total: {logs.length} events | Showing: {filteredLogs.length}
          </span>

          <button className="discover-refresh-btn" onClick={loadData}>
            <RefreshCw size={14} /> Refresh
          </button>
        </div>
      </div>

      <div className="discover-search-wrapper">
        <Search className="discover-search-icon" size={16} />
        <input
          type="text"
          placeholder="Search rule, host, user, event ID, IP, process, command..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="discover-search-input"
        />
      </div>

      <div className="discover-filter-bar">
        <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="INFO">Info</option>
        </select>

        <select value={hostFilter} onChange={(e) => setHostFilter(e.target.value)}>
          <option value="ALL">All Hosts</option>
          {hosts.map(h => <option key={h} value={h}>{h}</option>)}
        </select>

        <select value={eventFilter} onChange={(e) => setEventFilter(e.target.value)}>
          <option value="ALL">All Event IDs</option>
          {eventIds.map(eid => <option key={eid} value={eid}>{eid}</option>)}
        </select>

        <select value={timeFilter} onChange={(e) => setTimeFilter(e.target.value)}>
          <option value="ALL">All Time</option>
          <option value="1H">Last 1 Hour</option>
          <option value="24H">Last 24 Hours</option>
          <option value="7D">Last 7 Days</option>
          <option value="30D">Last 30 Days</option>
        </select>
      </div>

      <div className="discover-stats-grid">
        <div className="discover-stat-card">
          <div className="discover-stat-label">Visible Events</div>
          <div className="discover-stat-value">{filteredLogs.length}</div>
        </div>

        <div className="discover-stat-card">
          <div className="discover-stat-label">High/Critical</div>
          <div className="discover-stat-value" style={{ color: "#ff4444" }}>{highCritical}</div>
        </div>

        <div className="discover-stat-card">
          <div className="discover-stat-label">Unique Hosts</div>
          <div className="discover-stat-value" style={{ color: "#ffcc00" }}>{uniqueHosts}</div>
        </div>

        <div className="discover-stat-card">
          <div className="discover-stat-label">Raw Events</div>
          <div className="discover-stat-value" style={{ color: "#00cc88" }}>{logs.length}</div>
        </div>
      </div>

      <div className="discover-table-container">
        <div style={{ overflowX: "auto" }}>
          <table className="discover-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Host</th>
                <th>User</th>
                <th>Rule Description</th>
                <th>Event ID</th>
                <th>Level</th>
                <th>Severity</th>
                <th>Action</th>
              </tr>
            </thead>

            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="8" className="discover-loading">Loading security events...</td>
                </tr>
              ) : filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan="8" className="discover-empty">
                    <AlertTriangle size={24} />
                    <p>No events match current filters.</p>
                  </td>
                </tr>
              ) : (
                filteredLogs.slice(0, 300).map((log, idx) => {
                  const severity = mapSeverity(log.rule_level);

                  return (
                    <tr key={idx}>
                      <td className="discover-time">{formatTime(log.timestamp)}</td>

                      <td>
                        <span className="discover-host-cell">
                          <Server size={12} color="#00d4ff" /> {log.host || "-"}
                        </span>
                      </td>

                      <td>
                        <span className="discover-user-cell">
                          <User size={12} color="#00d4ff" /> {log.user ? String(log.user).split("\\").pop() : "-"}
                        </span>
                      </td>

                      <td>
                        <div className="discover-alert-title">
                          {log.rule_description || "Raw Wazuh Event"}
                        </div>
                        <div className="discover-alert-summary">
                          {(log.command_line || log.process || log.provider || "").slice(0, 120)}
                        </div>
                      </td>

                      <td className="discover-event-id">{log.event_id || "-"}</td>
                      <td>{log.rule_level ?? "-"}</td>

                      <td>
                        <span className={`discover-severity ${getSeverityClass(severity)}`}>
                          {severity}
                        </span>
                      </td>

                      <td>
                        <button className="discover-investigate-btn" onClick={() => investigate(log)}>
                          <Eye size={12} /> Investigate
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
    </div>
  );
}

function getSeverityClass(severity) {
  const s = String(severity || "INFO").toUpperCase();
  if (s === "CRITICAL") return "severity-critical";
  if (s === "HIGH") return "severity-high";
  if (s === "MEDIUM") return "severity-medium";
  return "severity-low";
}
