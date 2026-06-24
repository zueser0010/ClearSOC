import { useEffect, useMemo, useState } from "react";
import "../App.css";

export default function Suricata() {
  const [logs, setLogs] = useState([]);
  const [query, setQuery] = useState("");
  const [lastRefresh, setLastRefresh] = useState("");
  const [loading, setLoading] = useState(false);

  function loadLogs() {
    setLoading(true);

    fetch("http://localhost:8001/api/live-suricata?limit=1000")
      .then((res) => res.json())
      .then((data) => {
        setLogs(data.logs || []);
        setLastRefresh(new Date().toLocaleTimeString());
      })
      .catch(() => setLogs([]))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    loadLogs();
  }, []);

  const filtered = useMemo(() => {
    return logs.filter((log) =>
      JSON.stringify(log).toLowerCase().includes(query.toLowerCase())
    );
  }, [logs, query]);

  return (
    <div className="soc-page">
      <header className="soc-header">
        <div>
          <h1>Suricata IDS Logs</h1>
          <p>Live Suricata EVE JSON network detections</p>
          <small className="dash-meta">
            Last refresh: {lastRefresh || "Not refreshed yet"} | Loaded: {logs.length}
          </small>
        </div>

        <div className="soc-header-right">
          <input
            className="dash-select"
            placeholder="Search IP, signature, protocol..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />

          <button className="dash-refresh-btn" onClick={loadLogs}>
            {loading ? "Refreshing..." : "Refresh"}
          </button>
        </div>
      </header>

      <div className="soc-panel">
        <h2>Network Alerts</h2>

        <table className="soc-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Source IP</th>
              <th>Destination IP</th>
              <th>Protocol</th>
              <th>Signature</th>
              <th>Severity</th>
              <th>Category</th>
            </tr>
          </thead>

          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan="7">No Suricata logs found.</td>
              </tr>
            ) : (
              filtered.slice(0, 300).map((log, index) => (
                <tr key={index}>
                  <td>{log.timestamp || "N/A"}</td>
                  <td>{log.src_ip || "N/A"}</td>
                  <td>{log.dest_ip || "N/A"}</td>
                  <td>{log.proto || "N/A"}</td>
                  <td>{log.alert?.signature || log.event_type || "N/A"}</td>
                  <td>{log.alert?.severity || "N/A"}</td>
                  <td>{log.alert?.category || "N/A"}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
