import { useEffect, useState, useMemo } from "react";
import { Search, Play, Shield } from "lucide-react";

const API = "http://localhost:8001";

const HUNT_TEMPLATES = [
  {
    id: "powershell_abuse",
    name: "PowerShell Abuse Hunt",
    hypothesis: "Someone is using PowerShell to run hidden or encoded commands",
    tactic: "Execution",
    mitre: "T1059.001",
    difficulty: "Easy",
    description: "Searches for PowerShell processes with suspicious flags like -enc, -bypass, hidden window, or download commands.",
    filters: { event_id: "1", search: "powershell" },
    indicators: ["-enc", "-bypass", "hidden", "downloadstring", "iex"],
    color: "#f97316"
  },
  {
    id: "brute_force_hunt",
    name: "Brute Force Login Hunt",
    hypothesis: "Someone is trying to guess passwords on Windows accounts",
    tactic: "Credential Access",
    mitre: "T1110",
    difficulty: "Easy",
    description: "Searches for repeated failed login attempts (Event ID 4625) from the same source.",
    filters: { event_id: "4625", search: "" },
    indicators: ["4625", "administrator", "admin"],
    color: "#ef4444"
  },
  {
    id: "pass_the_hash",
    name: "Pass-the-Hash Hunt",
    hypothesis: "Someone is using stolen password hashes to log in without a password",
    tactic: "Lateral Movement",
    mitre: "T1550.002",
    difficulty: "Medium",
    description: "Searches for NTLM anonymous logon events, a classic sign of pass-the-hash attacks.",
    filters: { event_id: "4624", search: "anonymous" },
    indicators: ["anonymous logon", "ntlm"],
    color: "#ef4444"
  },
  {
    id: "account_enum",
    name: "Account Enumeration Hunt",
    hypothesis: "Someone is listing user accounts to plan their next move",
    tactic: "Discovery",
    mitre: "T1087",
    difficulty: "Easy",
    description: "Searches for net.exe / net1.exe execution, commonly used to list users and groups.",
    filters: { event_id: "1", search: "net.exe" },
    indicators: ["net.exe", "net1.exe", "net user"],
    color: "#eab308"
  },
  {
    id: "persistence_service",
    name: "Malicious Service Hunt",
    hypothesis: "An attacker installed a service to survive a reboot",
    tactic: "Persistence",
    mitre: "T1543.003",
    difficulty: "Medium",
    description: "Searches for Windows service configuration changes (Event ID 7040).",
    filters: { event_id: "7040", search: "" },
    indicators: ["7040", "service"],
    color: "#ef4444"
  },
  {
    id: "defense_evasion",
    name: "Audit Log Tampering Hunt",
    hypothesis: "Someone disabled Windows logging to hide their tracks",
    tactic: "Defense Evasion",
    mitre: "T1562.002",
    difficulty: "Medium",
    description: "Searches for audit policy changes (Event ID 4719), a common way attackers disable logging.",
    filters: { event_id: "4719", search: "" },
    indicators: ["4719", "audit policy"],
    color: "#eab308"
  },
  {
    id: "executable_drop",
    name: "Malware Drop Hunt",
    hypothesis: "Someone dropped a malicious file in a suspicious folder",
    tactic: "Persistence",
    mitre: "T1105",
    difficulty: "Easy",
    description: "Searches for executable files created in Windows system or temp folders.",
    filters: { event_id: "11", search: "executable" },
    indicators: ["11", "windows root", ".exe"],
    color: "#ef4444"
  },
  {
    id: "lateral_movement",
    name: "Lateral Movement Hunt",
    hypothesis: "An attacker is moving between computers using stolen credentials",
    tactic: "Lateral Movement",
    mitre: "T1021",
    difficulty: "Hard",
    description: "Searches for successful logins (Event ID 4624) that may indicate movement between hosts.",
    filters: { event_id: "4624", search: "" },
    indicators: ["4624", "network logon"],
    color: "#f97316"
  },
];

const DIFFICULTY_COLOR = { Easy: "#22c55e", Medium: "#eab308", Hard: "#ef4444" };
const TACTIC_COLOR = {
  "Execution": "#f97316", "Credential Access": "#ef4444",
  "Lateral Movement": "#f97316", "Discovery": "#06b6d4",
  "Persistence": "#ef4444", "Defense Evasion": "#eab308",
};

const HOST_NOTES = {
  alwin: "This is the Ubuntu server running ClearSOC and Wazuh itself, not a Windows endpoint. High counts here are usually normal system activity, not an attack.",
};

export default function ThreatIntel() {
  const [rawLogs, setRawLogs] = useState([]);
  const [activeHunt, setActiveHunt] = useState(null);
  const [huntResults, setHuntResults] = useState([]);
  const [huntRunning, setHuntRunning] = useState(false);
  const [huntComplete, setHuntComplete] = useState(false);
  const [customSearch, setCustomSearch] = useState("");
  const [savedHunts, setSavedHunts] = useState([]);
  const [activeTab, setActiveTab] = useState("templates");

  useEffect(() => {
    fetch(`${API}/api/raw-logs?limit=5000`)
      .then(r => r.json())
      .then(raw => setRawLogs(Array.isArray(raw) ? raw : (raw.logs || [])))
      .catch(() => {});
  }, []);

  function runHunt(template) {
    setActiveHunt(template);
    setActiveTab("results");
    setHuntRunning(true);
    setHuntComplete(false);
    setHuntResults([]);

    setTimeout(() => {
      const results = rawLogs.filter(log => {
        const matchEventId = !template.filters.event_id || log.event_id === template.filters.event_id;
        const searchTerm = template.filters.search.toLowerCase();
        const matchSearch = !searchTerm ||
          (log.rule_description || "").toLowerCase().includes(searchTerm) ||
          (log.process || "").toLowerCase().includes(searchTerm) ||
          (log.command_line || "").toLowerCase().includes(searchTerm) ||
          (log.user || "").toLowerCase().includes(searchTerm);
        return matchEventId && matchSearch;
      });

      setHuntResults(results);
      setHuntRunning(false);
      setHuntComplete(true);

      const hunt = {
        id: Date.now(),
        name: template.name,
        timestamp: new Date().toLocaleString(),
        results: results.length,
        mitre: template.mitre,
        tactic: template.tactic,
      };
      setSavedHunts(prev => [hunt, ...prev.slice(0, 9)]);
    }, 1200);
  }

  function runCustomHunt() {
    if (!customSearch.trim()) return;
    setHuntRunning(true);
    setHuntComplete(false);
    setHuntResults([]);
    setActiveHunt({ name: `Custom Hunt: "${customSearch}"`, color: "#38bdf8" });

    setTimeout(() => {
      const q = customSearch.toLowerCase();
      const results = rawLogs.filter(log =>
        (log.rule_description || "").toLowerCase().includes(q) ||
        (log.process || "").toLowerCase().includes(q) ||
        (log.command_line || "").toLowerCase().includes(q) ||
        (log.user || "").toLowerCase().includes(q) ||
        (log.host || "").toLowerCase().includes(q) ||
        (log.event_id || "").includes(q) ||
        (log.source_ip || "").includes(q)
      ).slice(0, 300);

      setHuntResults(results);
      setHuntRunning(false);
      setHuntComplete(true);
    }, 800);
  }

  const hostBreakdown = useMemo(() => {
    const map = {};
    huntResults.forEach(r => {
      const h = r.host || "unknown";
      map[h] = (map[h] || 0) + 1;
    });
    return Object.entries(map).sort((a, b) => b[1] - a[1]);
  }, [huntResults]);

  const windowsResults = huntResults.filter(r => r.host !== "alwin");
  const linuxResults = huntResults.filter(r => r.host === "alwin");

  return (
    <div style={{ padding: "20px", color: "#e2e8f0" }}>

      <div style={{ marginBottom: "20px" }}>
        <h1 style={{ fontSize: "24px", fontWeight: 700, color: "white", margin: 0 }}>Threat Hunting</h1>
        <p style={{ color: "#64748b", fontSize: "13px", margin: "4px 0 0" }}>
          Pick a hypothesis, run the hunt, see whether it&rsquo;s real. {rawLogs.length.toLocaleString()} events available to search.
        </p>
      </div>

      <div style={{ background: "rgba(56,189,248,0.05)", border: "1px solid rgba(56,189,248,0.15)", borderRadius: "10px", padding: "14px 18px", marginBottom: "20px", display: "flex", gap: "24px", flexWrap: "wrap" }}>
        {[
          { step: "1", title: "Pick a hypothesis", desc: "Choose a question like \"is someone brute-forcing logins?\"" },
          { step: "2", title: "Run the hunt", desc: "ClearSOC searches all collected events for matching evidence" },
          { step: "3", title: "Read the verdict", desc: "See how many matches were found and on which host" },
        ].map(s => (
          <div key={s.step} style={{ display: "flex", gap: "10px", alignItems: "flex-start", flex: "1", minWidth: "200px" }}>
            <div style={{ width: "24px", height: "24px", borderRadius: "50%", background: "rgba(56,189,248,0.15)", border: "1px solid #38bdf8", color: "#38bdf8", display: "flex", alignItems: "center", justifyContent: "center", fontSize: "12px", fontWeight: 700, flexShrink: 0 }}>{s.step}</div>
            <div>
              <p style={{ color: "#e2e8f0", fontSize: "13px", fontWeight: 600, margin: "0 0 2px" }}>{s.title}</p>
              <p style={{ color: "#64748b", fontSize: "11px", margin: 0 }}>{s.desc}</p>
            </div>
          </div>
        ))}
      </div>

      <div style={{ display: "flex", gap: "4px", marginBottom: "20px", borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
        {[
          { id: "templates", label: "Hunt Templates" },
          { id: "custom", label: "Custom Hunt" },
          { id: "results", label: "Results" },
          { id: "history", label: "History" },
        ].map(tab => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id)}
            style={{ background: "transparent", border: "none", borderBottom: `2px solid ${activeTab === tab.id ? "#38bdf8" : "transparent"}`, color: activeTab === tab.id ? "#38bdf8" : "#475569", padding: "10px 16px", cursor: "pointer", fontSize: "13px", fontWeight: 600, marginBottom: "-1px" }}>
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === "templates" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
          {HUNT_TEMPLATES.map(t => (
            <div key={t.id} style={{ background: "rgba(8,18,38,0.95)", border: `1px solid ${t.color}22`, borderRadius: "12px", padding: "18px" }}>
              <div style={{ marginBottom: "10px" }}>
                <h3 style={{ color: "white", fontSize: "14px", fontWeight: 700, margin: "0 0 6px" }}>{t.name}</h3>
                <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                  <span style={{ background: `${TACTIC_COLOR[t.tactic] || "#475569"}18`, border: `1px solid ${TACTIC_COLOR[t.tactic] || "#475569"}44`, color: TACTIC_COLOR[t.tactic] || "#475569", padding: "2px 8px", borderRadius: "4px", fontSize: "10px", fontWeight: 600 }}>{t.tactic}</span>
                  <span style={{ background: `${DIFFICULTY_COLOR[t.difficulty]}18`, border: `1px solid ${DIFFICULTY_COLOR[t.difficulty]}44`, color: DIFFICULTY_COLOR[t.difficulty], padding: "2px 8px", borderRadius: "4px", fontSize: "10px", fontWeight: 600 }}>{t.difficulty}</span>
                  <span style={{ background: "rgba(56,189,248,0.1)", color: "#38bdf8", padding: "2px 8px", borderRadius: "4px", fontSize: "10px", fontFamily: "monospace" }}>{t.mitre}</span>
                </div>
              </div>

              <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: "8px", padding: "10px", marginBottom: "12px" }}>
                <p style={{ color: "#94a3b8", fontSize: "11px", fontWeight: 600, margin: "0 0 4px" }}>Hypothesis</p>
                <p style={{ color: "#cbd5e1", fontSize: "12px", margin: "0 0 8px", fontStyle: "italic" }}>&ldquo;{t.hypothesis}&rdquo;</p>
                <p style={{ color: "#64748b", fontSize: "11px", margin: 0 }}>{t.description}</p>
              </div>

              <div style={{ marginBottom: "12px" }}>
                <p style={{ color: "#64748b", fontSize: "11px", margin: "0 0 6px" }}>Looking for:</p>
                <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
                  {t.indicators.map((ind, i) => (
                    <span key={i} style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.08)", color: "#94a3b8", padding: "2px 8px", borderRadius: "4px", fontSize: "10px", fontFamily: "monospace" }}>{ind}</span>
                  ))}
                </div>
              </div>

              <button onClick={() => runHunt(t)}
                style={{ width: "100%", background: `${t.color}18`, border: `1px solid ${t.color}44`, color: t.color, padding: "10px", borderRadius: "8px", cursor: "pointer", fontSize: "13px", fontWeight: 600, display: "flex", alignItems: "center", justifyContent: "center", gap: "8px" }}>
                <Play size={14} /> Run Hunt
              </button>
            </div>
          ))}
        </div>
      )}

      {activeTab === "custom" && (
        <div style={{ background: "rgba(8,18,38,0.95)", border: "1px solid rgba(56,189,248,0.12)", borderRadius: "12px", padding: "20px" }}>
          <h3 style={{ color: "white", fontSize: "15px", fontWeight: 600, margin: "0 0 8px" }}>Custom Hunt</h3>
          <p style={{ color: "#64748b", fontSize: "13px", margin: "0 0 16px" }}>Search collected events for anything specific - an IP, username, process, or event ID.</p>

          <div style={{ display: "flex", gap: "10px" }}>
            <div style={{ flex: 1, display: "flex", alignItems: "center", gap: "10px", background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: "8px", padding: "12px 16px" }}>
              <Search size={16} color="#475569" />
              <input value={customSearch} onChange={e => setCustomSearch(e.target.value)}
                onKeyDown={e => e.key === "Enter" && (setActiveTab("results"), runCustomHunt())}
                placeholder="e.g. 192.168.10.145, powershell, administrator..."
                style={{ background: "transparent", border: "none", outline: "none", color: "#e2e8f0", fontSize: "14px", width: "100%" }}
              />
            </div>
            <button onClick={() => { setActiveTab("results"); runCustomHunt(); }}
              style={{ background: "rgba(56,189,248,0.15)", border: "1px solid rgba(56,189,248,0.3)", color: "#38bdf8", padding: "12px 24px", borderRadius: "8px", cursor: "pointer", fontSize: "13px", fontWeight: 600, display: "flex", alignItems: "center", gap: "8px", whiteSpace: "nowrap" }}>
              <Play size={14} /> Hunt
            </button>
          </div>

          <div style={{ display: "flex", gap: "8px", marginTop: "12px", flexWrap: "wrap", alignItems: "center" }}>
            <p style={{ color: "#475569", fontSize: "11px", margin: 0 }}>Quick searches:</p>
            {["192.168.10.145", "powershell", "administrator", "anonymous logon", "net.exe", "4719"].map(q => (
              <button key={q} onClick={() => setCustomSearch(q)}
                style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", color: "#64748b", padding: "3px 10px", borderRadius: "4px", cursor: "pointer", fontSize: "11px", fontFamily: "monospace" }}>
                {q}
              </button>
            ))}
          </div>
        </div>
      )}

      {activeTab === "results" && (
        <div>
          {!activeHunt && (
            <div style={{ textAlign: "center", padding: "60px", color: "#475569" }}>
              Go to <b style={{ color: "#94a3b8" }}>Hunt Templates</b> or <b style={{ color: "#94a3b8" }}>Custom Hunt</b> and run a hunt to see results here.
            </div>
          )}

          {huntRunning && (
            <div style={{ textAlign: "center", padding: "60px", color: "#38bdf8" }}>
              <p style={{ fontSize: "15px", fontWeight: 600 }}>{activeHunt?.name}</p>
              <p style={{ color: "#64748b", fontSize: "13px" }}>Searching {rawLogs.length.toLocaleString()} events...</p>
            </div>
          )}

          {huntComplete && activeHunt && (
            <div>
              <div style={{ background: "rgba(8,18,38,0.95)", border: `1px solid ${activeHunt.color || "#38bdf8"}33`, borderRadius: "12px", padding: "18px", marginBottom: "16px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "12px" }}>
                  <div>
                    <h3 style={{ color: "white", fontSize: "15px", margin: "0 0 4px" }}>{activeHunt.name}</h3>
                    {activeHunt.hypothesis && <p style={{ color: "#94a3b8", fontSize: "12px", margin: 0, fontStyle: "italic" }}>&ldquo;{activeHunt.hypothesis}&rdquo;</p>}
                  </div>
                  <div style={{ display: "flex", gap: "12px", alignItems: "center" }}>
                    {activeHunt.mitre && <span style={{ color: "#38bdf8", fontSize: "12px", fontFamily: "monospace" }}>{activeHunt.mitre}</span>}
                    <span style={{ color: huntResults.length > 50 ? "#ef4444" : huntResults.length > 0 ? "#eab308" : "#22c55e", fontWeight: 700, fontSize: "22px" }}>{huntResults.length.toLocaleString()}</span>
                    <span style={{ color: "#64748b", fontSize: "12px" }}>matches</span>
                  </div>
                </div>

                {huntResults.length === 0 ? (
                  <div style={{ marginTop: "14px", padding: "12px", background: "rgba(34,197,94,0.08)", border: "1px solid rgba(34,197,94,0.2)", borderRadius: "8px" }}>
                    <p style={{ color: "#22c55e", fontWeight: 600, margin: 0, fontSize: "13px" }}>No matches found - this hypothesis is not confirmed in your environment right now.</p>
                  </div>
                ) : windowsResults.length === 0 ? (
                  <div style={{ marginTop: "14px", padding: "12px", background: "rgba(234,179,8,0.08)", border: "1px solid rgba(234,179,8,0.2)", borderRadius: "8px" }}>
                    <p style={{ color: "#eab308", fontWeight: 600, margin: "0 0 4px", fontSize: "13px" }}>All {huntResults.length} matches are from your Ubuntu/Wazuh server (host: alwin)</p>
                    <p style={{ color: "#64748b", fontSize: "12px", margin: 0 }}>{HOST_NOTES.alwin} No Windows endpoints triggered this hunt - likely a false positive for this hypothesis.</p>
                  </div>
                ) : (
                  <div style={{ marginTop: "14px", padding: "12px", background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.2)", borderRadius: "8px" }}>
                    <p style={{ color: "#ef4444", fontWeight: 600, margin: "0 0 4px", fontSize: "13px" }}>{windowsResults.length} match(es) found on Windows endpoints - worth investigating</p>
                    <p style={{ color: "#64748b", fontSize: "12px", margin: 0 }}>Review the breakdown below and open the matching alerts in Investigation if available.</p>
                  </div>
                )}
              </div>

              {hostBreakdown.length > 0 && (
                <div style={{ background: "rgba(8,18,38,0.95)", border: "1px solid rgba(56,189,248,0.1)", borderRadius: "12px", padding: "16px", marginBottom: "16px" }}>
                  <p style={{ color: "#64748b", fontSize: "11px", fontWeight: 600, textTransform: "uppercase", margin: "0 0 12px" }}>Matches by Host</p>
                  <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                    {hostBreakdown.map(([host, count]) => (
                      <div key={host}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                          <span style={{ color: host === "alwin" ? "#64748b" : "#e2e8f0", fontSize: "13px", fontWeight: 600 }}>
                            {host} {host === "alwin" && <span style={{ color: "#475569", fontWeight: 400, fontSize: "11px" }}>(this server, not an attack target)</span>}
                          </span>
                          <span style={{ color: host === "alwin" ? "#64748b" : "#f97316", fontWeight: 700, fontSize: "13px" }}>{count.toLocaleString()}</span>
                        </div>
                        <div style={{ height: "6px", background: "rgba(255,255,255,0.05)", borderRadius: "3px", overflow: "hidden" }}>
                          <div style={{ height: "100%", width: `${(count / huntResults.length) * 100}%`, background: host === "alwin" ? "#475569" : "#f97316" }} />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {windowsResults.length > 0 && (
                <>
                  <p style={{ color: "#64748b", fontSize: "11px", fontWeight: 600, textTransform: "uppercase", margin: "0 0 8px" }}>Windows Endpoint Events ({windowsResults.length})</p>
                  <HuntResultsTable results={windowsResults.slice(0, 100)} />
                </>
              )}

              {linuxResults.length > 0 && (
                <details style={{ marginTop: "12px" }}>
                  <summary style={{ color: "#475569", fontSize: "12px", cursor: "pointer", padding: "8px 0" }}>
                    Show {linuxResults.length.toLocaleString()} server-side events from 'alwin' (usually not relevant to attack hunting)
                  </summary>
                  <div style={{ marginTop: "8px" }}>
                    <HuntResultsTable results={linuxResults.slice(0, 50)} />
                  </div>
                </details>
              )}
            </div>
          )}
        </div>
      )}

      {activeTab === "history" && (
        <div style={{ background: "rgba(8,18,38,0.95)", border: "1px solid rgba(56,189,248,0.12)", borderRadius: "12px", padding: "20px" }}>
          <h3 style={{ color: "white", fontSize: "14px", fontWeight: 600, margin: "0 0 14px" }}>Hunt History</h3>
          {savedHunts.length === 0 ? (
            <p style={{ color: "#475569", textAlign: "center", padding: "40px 0" }}>No hunts run yet. Go to Hunt Templates and run your first hunt.</p>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              {savedHunts.map(h => (
                <div key={h.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 16px", background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: "8px" }}>
                  <div>
                    <p style={{ color: "#e2e8f0", fontWeight: 600, fontSize: "13px", margin: "0 0 4px" }}>{h.name}</p>
                    <p style={{ color: "#475569", fontSize: "11px", margin: 0 }}>{h.timestamp} - {h.tactic} - {h.mitre}</p>
                  </div>
                  <span style={{ color: h.results > 0 ? "#ef4444" : "#22c55e", fontWeight: 700, fontSize: "14px" }}>
                    {h.results.toLocaleString()} events
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "20px", padding: "14px", background: "rgba(56,189,248,0.05)", border: "1px solid rgba(56,189,248,0.1)", borderRadius: "8px" }}>
        <Shield size={16} color="#38bdf8" />
        <span style={{ color: "#64748b", fontSize: "12px" }}>Threat hunting is proactive: you choose what to look for, run the search, and decide if it&rsquo;s real - unlike alerts, which fire automatically.</span>
      </div>
    </div>
  );
}

function HuntResultsTable({ results }) {
  if (results.length === 0) return null;
  return (
    <div style={{ background: "rgba(8,18,38,0.95)", border: "1px solid rgba(56,189,248,0.1)", borderRadius: "12px", overflow: "hidden" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
        <thead>
          <tr>
            {["Time", "Host", "User", "Event ID", "Description"].map(h => (
              <th key={h} style={{ color: "#475569", fontWeight: 600, padding: "10px 12px", textAlign: "left", borderBottom: "1px solid rgba(255,255,255,0.06)", fontSize: "10px", textTransform: "uppercase", background: "rgba(0,0,0,0.2)" }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {results.map((r, i) => (
            <tr key={i} style={{ borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
              <td style={{ padding: "8px 12px", fontFamily: "monospace", color: "#64748b", fontSize: "11px", whiteSpace: "nowrap" }}>
                {r.timestamp?.replace("T", " ")?.split("+")[0]?.slice(0, 16)}
              </td>
              <td style={{ padding: "8px 12px", color: "#e2e8f0" }}>{r.host}</td>
              <td style={{ padding: "8px 12px", color: "#94a3b8" }}>{r.user || "-"}</td>
              <td style={{ padding: "8px 12px", color: "#38bdf8", fontFamily: "monospace" }}>{r.event_id || "-"}</td>
              <td style={{ padding: "8px 12px", color: "#64748b", maxWidth: "400px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.rule_description}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
