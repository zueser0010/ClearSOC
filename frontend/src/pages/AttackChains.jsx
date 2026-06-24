import { useNavigate } from "react-router-dom";
import { useEffect, useState } from "react";
import {
  Link2,
  ShieldAlert,
  Activity,
  Eye,
  FileText,
  AlertTriangle,
  Clock,
  Server
} from "lucide-react";
import "../App.css";

const API_URL = "http://localhost:8001/api/attack-chains";

const PHASE_COLOR = {
  "Initial Access": "#f97316",
  "Execution": "#f97316",
  "Persistence": "#ef4444",
  "Privilege Escalation": "#ef4444",
  "Defense Evasion": "#eab308",
  "Credential Access": "#ef4444",
  "Discovery": "#06b6d4",
  "Lateral Movement": "#ef4444",
  "Collection": "#a855f7",
  "Exfiltration": "#a855f7",
  "Unknown": "#64748b",
};

function formatTime(value) {
  if (!value) return "N/A";
  const d = new Date(value);
  if (isNaN(d.getTime())) return "N/A";
  return d.toLocaleString();
}

// Fixes "T1082T1087" -> "T1082, T1087" without touching already-correct values
function formatMitre(raw) {
  if (!raw) return "";
  if (Array.isArray(raw)) return raw.join(", ");
  return String(raw).replace(/(T\d{4}(?:\.\d{3})?)(?=T\d{4})/g, "$1, ");
}

function categorizeEvent(ev) {
  const text = `${ev.stage || ""} ${ev.event || ""} ${ev.details || ""}`.toLowerCase();
  const mitre = formatMitre(ev.mitre).toLowerCase();

  if (text.includes("failed login") || text.includes("authentication failure") || text.includes("brute force") || mitre.includes("t1110")) {
    return "failed_login";
  }
  if (text.includes("successful login") || text.includes("successful remote logon") || text.includes("pass-the-hash") || text.includes("anonymous logon")) {
    return "successful_login";
  }
  if (text.includes("privilege") || mitre.includes("t1078")) {
    return "privilege_escalation";
  }
  if (text.includes("service configuration") || text.includes("persistence") || text.includes("admin group") || mitre.includes("t1543") || mitre.includes("t1098")) {
    return "persistence";
  }
  if (text.includes("dropped") || text.includes("executable") || mitre.includes("t1105")) {
    return "malware_drop";
  }
  if (text.includes("powershell") || mitre.includes("t1059.001")) {
    return "powershell";
  }
  if (text.includes("discovery") || mitre.includes("t1082") || mitre.includes("t1087")) {
    return "discovery";
  }
  if (text.includes("audit policy") || mitre.includes("t1562")) {
    return "defense_evasion";
  }
  return "other";
}

function buildNarrative(timeline) {
  if (!timeline || timeline.length === 0) return [];

  const sorted = [...timeline].sort((a, b) => new Date(a.time) - new Date(b.time));

  const groups = [];
  sorted.forEach((ev) => {
    const cat = categorizeEvent(ev);
    const last = groups[groups.length - 1];
    if (last && last.category === cat) {
      last.events.push(ev);
    } else {
      groups.push({ category: cat, events: [ev] });
    }
  });

  return groups.map((g, idx) => {
    const first = g.events[0];
    const lastEv = g.events[g.events.length - 1];
    const count = g.events.length;
    const t1 = formatTime(first.time);
    const t2 = formatTime(lastEv.time);
    const phase = first.kill_chain_phase || first.stage || "Unknown";
    const mitreList = [...new Set(g.events.map(e => formatMitre(e.mitre)).filter(Boolean))];

    let text = "";
    switch (g.category) {
      case "failed_login":
        text = count > 1
          ? `${count} failed login attempts observed between ${t1} and ${t2}`
          : `A failed login attempt was observed at ${t1}`;
        break;
      case "successful_login": {
        const prevWasFailed = idx > 0 && groups[idx - 1].category === "failed_login";
        text = prevWasFailed
          ? `Successful login at ${t1} — likely the attacker gaining access after the failed attempts above (Initial Access)`
          : `Successful login at ${t1} — account access was granted`;
        break;
      }
      case "privilege_escalation":
        text = `Account received elevated privileges at ${t1}`;
        break;
      case "persistence":
        text = count > 1
          ? `${count} persistence-related changes made between ${t1} and ${t2} (service or group membership changes)`
          : `A persistence mechanism was set up at ${t1}`;
        break;
      case "malware_drop":
        text = count > 1
          ? `${count} suspicious files were dropped onto disk between ${t1} and ${t2}`
          : `A suspicious file was dropped onto disk at ${t1}`;
        break;
      case "powershell":
        text = `Suspicious PowerShell activity (encoded or policy-bypass command) at ${t1}`;
        break;
      case "discovery":
        text = `The attacker began exploring the system (listing users, groups, or system info) starting at ${t1}`;
        break;
      case "defense_evasion":
        text = `Audit/logging policy was changed at ${t1} — a common way attackers try to reduce visibility`;
        break;
      default:
        text = count > 1
          ? `${first.event || "Activity"} occurred ${count} times between ${t1} and ${t2}`
          : `${first.event || "Activity"} occurred at ${t1}`;
    }

    return { step: idx + 1, category: g.category, phase, text, t1, t2, count, mitre: mitreList, events: g.events };
  });
}

export default function AttackChains() {
  const navigate = useNavigate();
  const [chains, setChains] = useState([]);
  const [openRow, setOpenRow] = useState(null);
  const [lastRefresh, setLastRefresh] = useState("");

  function fetchChains() {
    fetch(API_URL)
      .then((res) => res.json())
      .then((data) => {
        setChains(Array.isArray(data) ? data : []);
        setLastRefresh(new Date().toLocaleTimeString());
      })
      .catch(() => setChains([]));
  }

  useEffect(() => {
    fetchChains();
  }, []);

  const high = chains.filter((c) => getConfidence(c) === "HIGH").length;
  const medium = chains.filter((c) => getConfidence(c) === "MEDIUM").length;
  const low = chains.filter((c) => getConfidence(c) === "LOW").length;

  return (
    <div className="attack-page">
      <div className="attack-header">
        <div>
          <h1>Attack Chains</h1>
          <p>Correlated multi-stage attack visibility</p>
        </div>

        <button onClick={fetchChains}>Refresh</button>
      </div>

      <div className="attack-meta">
        <span className="online-dot"></span>
        System Online | Last refresh: {lastRefresh || "Not refreshed yet"}
      </div>

      <section className="attack-kpi-grid">
        <AttackKpi title="Total Chains" value={chains.length} icon={<Link2 />} color="cyan" />
        <AttackKpi title="High Confidence" value={high} icon={<ShieldAlert />} color="red" />
        <AttackKpi title="Medium Confidence" value={medium} icon={<AlertTriangle />} color="yellow" />
        <AttackKpi title="Low Confidence" value={low} icon={<Activity />} color="green" />
      </section>

      <section className="attack-panel">
        <div className="attack-panel-title">
          <h2>Recent Attack Chains</h2>
          <span>{chains.length} chains</span>
        </div>

        <table className="attack-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Chain Type</th>
              <th>Host</th>
              <th>User</th>
              <th>Start Time</th>
              <th>Severity</th>
              <th>Confidence</th>
              <th>Decision</th>
            </tr>
          </thead>

          <tbody>
            {chains.length === 0 ? (
              <tr>
                <td colSpan="8">No attack chains detected.</td>
              </tr>
            ) : (
              chains.map((chain, index) => {
                const confidence = getConfidence(chain);
                const severity = getSeverity(chain);
                const timeline = chain.timeline || [];
                const narrative = buildNarrative(timeline);

                const times = timeline.map(e => e.time).filter(Boolean).sort();
                const startTime = times.length > 0 ? new Date(times[0]).toLocaleString() : "N/A";
                const endTime = times.length > 0 ? new Date(times[times.length - 1]).toLocaleString() : "N/A";

                return (
                  <>
                    <tr
                      className="attack-row"
                      onClick={() => setOpenRow(openRow === index ? null : index)}
                    >
                      <td>{index + 1}</td>
                      <td>{chain.chain_label || chain.chain_type || "Unknown Chain"}</td>
                      <td>{chain.host || "N/A"}</td>
                      <td>{chain.user || "N/A"}</td>
                      <td>{startTime}</td>
                      <td><Badge value={severity} /></td>
                      <td><Badge value={confidence} /></td>
                      <td><Badge value={chain.decision || "INVESTIGATE"} /></td>
                    </tr>

                    {openRow === index && (
                      <tr className="attack-expanded-row">
                        <td colSpan="8">
                          <div className="attack-expand-box">
                            <div className="attack-expand-head">
                              <div>
                                <h3>{chain.chain_label || chain.chain_type}</h3>
                                <p>{chain.summary || "No summary available."}</p>
                              </div>

                              <div className="attack-badge-group">
                                <Badge value={severity} />
                                <Badge value={confidence} />
                              </div>
                            </div>

                            <div className="attack-detail-grid">
                              <Detail icon={<Server />} label="Host" value={chain.host} />
                              <Detail icon={<Activity />} label="User" value={chain.user} />
                              <Detail icon={<Clock />} label="Start Time" value={startTime} />
                              <Detail icon={<Clock />} label="End Time" value={endTime} />
                            </div>

                            {/* NARRATIVE STORY */}
                            <div style={{ marginTop: "20px" }}>
                              <h3 style={{ color: "white", fontSize: "15px", marginBottom: "4px" }}>What Happened</h3>
                              {narrative.length > 0 && (
                                <p style={{ color: "#64748b", fontSize: "12px", marginBottom: "14px" }}>
                                  This incident unfolded across {narrative.length} stage{narrative.length === 1 ? "" : "s"}, from {narrative[0].t1} to {narrative[narrative.length - 1].t2}.
                                </p>
                              )}

                              {narrative.length === 0 ? (
                                <p style={{ color: "#64748b", fontSize: "13px" }}>No timeline available.</p>
                              ) : (
                                <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                                  {narrative.map((step) => {
                                    const color = PHASE_COLOR[step.phase] || PHASE_COLOR.Unknown;
                                    return (
                                      <div key={step.step} style={{
                                        display: "flex", gap: "12px",
                                        background: "rgba(255,255,255,0.03)",
                                        border: `1px solid ${color}33`,
                                        borderRadius: "8px", padding: "12px 14px"
                                      }}>
                                        <div style={{
                                          width: "26px", height: "26px", borderRadius: "50%",
                                          background: `${color}1f`, border: `1px solid ${color}`,
                                          color, display: "flex", alignItems: "center", justifyContent: "center",
                                          fontSize: "12px", fontWeight: 700, flexShrink: 0
                                        }}>{step.step}</div>
                                        <div style={{ flex: 1 }}>
                                          <div style={{ display: "flex", gap: "8px", alignItems: "center", marginBottom: "4px", flexWrap: "wrap" }}>
                                            <span style={{
                                              background: `${color}18`, border: `1px solid ${color}44`, color,
                                              padding: "1px 8px", borderRadius: "4px", fontSize: "10px", fontWeight: 600
                                            }}>{step.phase}</span>
                                            {step.mitre.map((m, i) => (
                                              <span key={i} style={{ color: "#38bdf8", fontSize: "11px", fontFamily: "monospace" }}>{m}</span>
                                            ))}
                                          </div>
                                          <p style={{ color: "#e2e8f0", fontSize: "13px", margin: 0, lineHeight: "1.5" }}>{step.text}</p>
                                        </div>
                                      </div>
                                    );
                                  })}
                                </div>
                              )}

                              <details style={{ marginTop: "16px" }}>
                                <summary style={{ color: "#475569", fontSize: "12px", cursor: "pointer" }}>
                                  View raw event log ({timeline.length} events)
                                </summary>
                                <div className="attack-timeline" style={{ marginTop: "10px" }}>
                                  {timeline.map((event, i) => (
                                    <div className="attack-timeline-card" key={i}>
                                      <div className="timeline-dot"></div>
                                      <div>
                                        <h4>{event.stage || "Event"} — {event.event || "Activity"}</h4>
                                        <p><b>Time:</b> {formatTime(event.time)}</p>
                                        <p><b>MITRE:</b> {formatMitre(event.mitre) || "N/A"}</p>
                                        <p><b>Details:</b> {event.details || "N/A"}</p>
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              </details>
                            </div>

                            <div className="attack-actions">
                              <button
                                onClick={() => {
                                  localStorage.setItem("clearsoc_selected_attack_chain", JSON.stringify(chain));

                                  const realAlert =
                                    Array.isArray(chain.alerts) && chain.alerts.length > 0
                                      ? chain.alerts[0]
                                      : null;

                                  const selected = realAlert
                                    ? {
                                        ...realAlert,
                                        related_chain_id: chain.chain_id,
                                        chain_data: chain,
                                        chain_severity: chain.severity,
                                        confidence: chain.confidence,
                                        chain_reasons: chain.reasons || [],
                                        chain_kill_chain_phases: chain.kill_chain_phases || [],
                                        title: realAlert.title || chain.chain_label || "Attack Chain Investigation",
                                        summary: realAlert.summary || chain.summary || "Attack chain selected for investigation"
                                      }
                                    : {
                                        alert_id: chain.chain_id || `CHAIN-${index}`,
                                        title: chain.chain_label || chain.chain_type || "Attack Chain Investigation",
                                        summary: chain.summary || "Attack chain selected for investigation",
                                        host: chain.host,
                                        user: chain.user,
                                        severity: severity,
                                        time: startTime,
                                        kill_chain_phase: (chain.kill_chain_phases || []).join(" → "),
                                        mitre: chain.mitre || [],
                                        recommended_actions: chain.recommended_actions || [],
                                        related_chain_id: chain.chain_id,
                                        chain_data: chain,
                                        chain_reasons: chain.reasons || [],
                                        chain_kill_chain_phases: chain.kill_chain_phases || []
                                      };

                                  localStorage.setItem("clearsoc_selected_alert", JSON.stringify(selected));
                                  navigate("/investigation");
                                }}
                              >
                                <Eye size={15} /> Investigate
                              </button>
                              <button><FileText size={15} /> Generate Report</button>
                              <button>Run SOAR</button>
                              <button>Escalate L2</button>
                              <button className="danger-btn">Block IP</button>
                              <button className="danger-btn">Isolate Host</button>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                );
              })
            )}
          </tbody>
        </table>
      </section>
    </div>
  );
}

function getConfidence(chain) {
  return String(chain.confidence_level || chain.confidence || "LOW").toUpperCase();
}

function getSeverity(chain) {
  return String(chain.severity || chain.timeline?.[0]?.severity || "MEDIUM").toUpperCase();
}

function AttackKpi({ title, value, icon, color }) {
  return (
    <div className={`attack-kpi ${color}`}>
      <div>
        <p>{title}</p>
        <h2>{value}</h2>
      </div>
      <div className="attack-kpi-icon">{icon}</div>
    </div>
  );
}

function Detail({ icon, label, value }) {
  return (
    <div className="attack-detail-card">
      {icon}
      <div>
        <p>{label}</p>
        <h4>{value || "N/A"}</h4>
      </div>
    </div>
  );
}

function Badge({ value }) {
  const clean = String(value || "N/A").toUpperCase();
  return <span className={`attack-badge ${clean.toLowerCase()}`}>{clean}</span>;
}
