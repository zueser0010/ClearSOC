import { useState, useEffect } from "react";
import { 
  Server, Shield, Bell, Database, Settings as Cog, 
  Play, CheckCircle, XCircle, RefreshCw, 
  FileText, Users, Lock, AlertTriangle, 
  Plus, Trash2, Edit2, Activity, Cpu, 
  HardDrive, Globe, Zap, Cloud, Network,
  Key, Clock, BarChart, PieChart, Mail, Phone,
  Wifi, Monitor, Terminal, Code, FolderOpen,
  MessageCircle, Send, Mail as MailIcon, 
  Smartphone, AlertOctagon, Webhook
} from "lucide-react";

const API = "http://localhost:8001";

export default function Settings() {
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [activeTab, setActiveTab] = useState("workspace");
  const [running, setRunning] = useState(false);
  const [pipelineResult, setPipelineResult] = useState(null);

  // Escalation settings state
  const [escalation, setEscalation] = useState({
    email: "",
    whatsapp: "",
    sms: "",
    slack: "",
    teams: "",
    pagerduty: "",
    autoEscalate: true,
    escalateAfter: 30,
    criticalOnly: false
  });

  useEffect(() => {
    fetchSettings();
  }, []);

  const fetchSettings = async () => {
    try {
      const res = await fetch(`${API}/api/settings`);
      const data = await res.json();
      setConfig(data);
      if (data.escalation) {
        setEscalation(data.escalation);
      }
    } catch (e) {
      console.error("Failed to load settings:", e);
    } finally {
      setLoading(false);
    }
  };

  const saveSettings = async () => {
    setSaving(true);
    try {
      const payload = {
        ...config,
        escalation: escalation
      };
      await fetch(`${API}/api/settings`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (e) {
      console.error("Failed to save:", e);
    } finally {
      setSaving(false);
    }
  };

  const runPipeline = async () => {
    setRunning(true);
    setPipelineResult(null);
    try {
      const res = await fetch(`${API}/api/settings/run-pipeline`, { method: "POST" });
      const data = await res.json();
      setPipelineResult(data);
      await fetchSettings();
    } catch (e) {
      setPipelineResult({ status: "error", message: String(e) });
    } finally {
      setRunning(false);
    }
  };

  if (loading) {
    return (
      <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "100vh", color: "#64748b" }}>
        <RefreshCw size={24} style={{ animation: "spin 1s linear infinite" }} />
        <span style={{ marginLeft: "12px" }}>Loading settings...</span>
      </div>
    );
  }

  if (!config) {
    return (
      <div style={{ padding: "40px", textAlign: "center", color: "#ef4444" }}>
        <AlertTriangle size={32} />
        <p style={{ marginTop: "12px" }}>Failed to load settings. Please check backend API.</p>
      </div>
    );
  }

  const tabs = [
    { id: "workspace", label: "Workspace", icon: Cloud },
    { id: "escalation", label: "Escalation", icon: Bell },
    { id: "datasources", label: "Data Sources", icon: Database },
    { id: "detection", label: "Detection", icon: Shield },
    { id: "retention", label: "Retention", icon: Clock },
    { id: "permissions", label: "Permissions", icon: Key },
    { id: "automation", label: "Automation", icon: Zap },
    { id: "system", label: "System", icon: Activity }
  ];

  return (
    <div style={{ padding: "24px", background: "#0a0c10", minHeight: "100vh", color: "#e2e8f0" }}>
      
      {/* HEADER */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "24px", flexWrap: "wrap", gap: "12px" }}>
        <div>
          <h1 style={{ fontSize: "24px", fontWeight: "700", color: "white", margin: 0, display: "flex", alignItems: "center", gap: "10px" }}>
            <Cog size={24} color="#38bdf8" /> Settings
          </h1>
          <p style={{ color: "#64748b", fontSize: "13px", margin: "4px 0 0" }}>Configure ClearSOC workspace, data sources, and security monitoring</p>
        </div>
        <div style={{ display: "flex", gap: "10px" }}>
          <button 
            onClick={saveSettings} 
            disabled={saving}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              background: saved ? "rgba(34,197,94,0.15)" : "rgba(56,189,248,0.15)",
              border: `1px solid ${saved ? "rgba(34,197,94,0.3)" : "rgba(56,189,248,0.3)"}`,
              color: saved ? "#22c55e" : "#38bdf8",
              padding: "10px 24px",
              borderRadius: "8px",
              cursor: "pointer",
              fontSize: "13px",
              fontWeight: "600"
            }}
          >
            {saved ? <><CheckCircle size={14}/> Saved</> : <><Save size={14}/> {saving ? "Saving..." : "Save Settings"}</>}
          </button>
        </div>
      </div>

      {/* TABS */}
      <div style={{ 
        display: "flex", 
        gap: "4px", 
        marginBottom: "24px", 
        background: "rgba(8,18,38,0.95)", 
        border: "1px solid rgba(56,189,248,0.08)", 
        borderRadius: "12px", 
        padding: "4px",
        overflowX: "auto",
        flexWrap: "nowrap"
      }}>
        {tabs.map(tab => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "6px",
                padding: "10px 16px",
                borderRadius: "8px",
                border: "none",
                background: activeTab === tab.id ? "rgba(56,189,248,0.12)" : "transparent",
                color: activeTab === tab.id ? "#38bdf8" : "#64748b",
                cursor: "pointer",
                fontSize: "12px",
                fontWeight: activeTab === tab.id ? "600" : "400",
                whiteSpace: "nowrap"
              }}
            >
              <Icon size={15} /> {tab.label}
            </button>
          );
        })}
      </div>

      {/* CONTENT */}
      <div>
        {activeTab === "workspace" && <WorkspaceTab config={config} setConfig={setConfig} />}
        {activeTab === "escalation" && <EscalationTab escalation={escalation} setEscalation={setEscalation} />}
        {activeTab === "datasources" && <DataSourcesTab config={config} setConfig={setConfig} />}
        {activeTab === "detection" && <DetectionTab config={config} setConfig={setConfig} />}
        {activeTab === "retention" && <RetentionTab config={config} setConfig={setConfig} />}
        {activeTab === "permissions" && <PermissionsTab config={config} setConfig={setConfig} />}
        {activeTab === "automation" && <AutomationTab config={config} runPipeline={runPipeline} running={running} pipelineResult={pipelineResult} />}
        {activeTab === "system" && <SystemTab config={config} />}
      </div>

      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        .settings-card {
          background: rgba(8,18,38,0.95);
          border: 1px solid rgba(56,189,248,0.08);
          border-radius: 12px;
          padding: 20px;
          margin-bottom: 16px;
        }
        .settings-input {
          background: rgba(255,255,255,0.05);
          border: 1px solid rgba(255,255,255,0.08);
          color: #e2e8f0;
          padding: 10px 14px;
          border-radius: 8px;
          font-size: 13px;
          width: 100%;
          outline: none;
          transition: border-color 0.2s;
          box-sizing: border-box;
        }
        .settings-input:focus {
          border-color: rgba(56,189,248,0.4);
        }
        .settings-input::placeholder {
          color: #475569;
        }
        .settings-select {
          background: rgba(255,255,255,0.05);
          border: 1px solid rgba(255,255,255,0.08);
          color: #e2e8f0;
          padding: 10px 14px;
          border-radius: 8px;
          font-size: 13px;
          width: 100%;
          outline: none;
          box-sizing: border-box;
        }
        .settings-label {
          color: #94a3b8;
          font-size: 12px;
          font-weight: 600;
          display: block;
          margin-bottom: 6px;
        }
        .settings-hint {
          color: #475569;
          font-size: 11px;
          margin: 4px 0 0;
        }
        .status-badge-online {
          display: inline-flex;
          align-items: center;
          gap: 4px;
          color: #22c55e;
          font-size: 12px;
          font-weight: 600;
        }
        .escalation-channel {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 12px 16px;
          background: rgba(255,255,255,0.03);
          border: 1px solid rgba(255,255,255,0.06);
          border-radius: 8px;
          margin-bottom: 8px;
        }
        .escalation-channel:hover {
          background: rgba(255,255,255,0.05);
        }
      `}</style>
    </div>
  );
}

// ==================== ESCALATION TAB ====================

function EscalationTab({ escalation, setEscalation }) {
  const channels = [
    { id: "email", label: "Email", icon: MailIcon, placeholder: "soc-team@company.com", hint: "Email address for SOC team" },
    { id: "whatsapp", label: "WhatsApp", icon: MessageCircle, placeholder: "+6591234567", hint: "Include country code" },
    { id: "sms", label: "SMS", icon: Smartphone, placeholder: "+6591234567", hint: "Include country code" },
    { id: "slack", label: "Slack", icon: Send, placeholder: "https://hooks.slack.com/services/XXX/XXX", hint: "Slack webhook URL" },
    { id: "teams", label: "Teams", icon: Webhook, placeholder: "https://company.webhook.office.com/...", hint: "Microsoft Teams webhook URL" },
    { id: "pagerduty", label: "PagerDuty", icon: AlertOctagon, placeholder: "https://events.pagerduty.com/...", hint: "PagerDuty integration URL" }
  ];

  return (
    <div>
      <div className="settings-card">
        <h3 style={{ color: "#38bdf8", fontSize: "14px", fontWeight: "600", marginBottom: "12px" }}>
          <Bell size={16} style={{ display: "inline", marginRight: "8px" }} /> Escalation Channels
        </h3>
        <p style={{ color: "#64748b", fontSize: "12px", marginBottom: "16px" }}>
          Configure escalation channels for alert notifications. These will be used when an alert is escalated in the Investigation page.
        </p>
        
        <div style={{ display: "grid", gap: "10px" }}>
          {channels.map(ch => {
            const Icon = ch.icon;
            const value = escalation[ch.id] || "";
            return (
              <div key={ch.id} className="escalation-channel">
                <div style={{ 
                  display: "flex", 
                  alignItems: "center", 
                  justifyContent: "center",
                  width: "36px", 
                  height: "36px", 
                  borderRadius: "8px",
                  background: "rgba(56,189,248,0.1)",
                  color: "#38bdf8",
                  flexShrink: 0
                }}>
                  <Icon size={18} />
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <label className="settings-label" style={{ marginBottom: 0, fontSize: "13px" }}>{ch.label}</label>
                    {value && <span style={{ fontSize: "10px", color: "#22c55e", fontWeight: "600" }}>✓ Configured</span>}
                  </div>
                  <input 
                    className="settings-input" 
                    value={value}
                    onChange={e => setEscalation({...escalation, [ch.id]: e.target.value})}
                    placeholder={ch.placeholder}
                    style={{ marginTop: "4px", fontSize: "12px" }}
                  />
                  <div className="settings-hint">{ch.hint}</div>
                </div>
                {value && (
                  <button 
                    onClick={() => setEscalation({...escalation, [ch.id]: ""})}
                    style={{
                      background: "rgba(239,68,68,0.1)",
                      border: "1px solid rgba(239,68,68,0.2)",
                      color: "#ef4444",
                      padding: "4px 12px",
                      borderRadius: "6px",
                      cursor: "pointer",
                      fontSize: "11px"
                    }}
                  >
                    Clear
                  </button>
                )}
              </div>
            );
          })}
        </div>
      </div>

      <div className="settings-card">
        <h3 style={{ color: "#38bdf8", fontSize: "14px", fontWeight: "600", marginBottom: "12px" }}>
          <AlertOctagon size={16} style={{ display: "inline", marginRight: "8px" }} /> Escalation Rules
        </h3>
        
        <div style={{ display: "grid", gap: "14px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 14px", background: "rgba(255,255,255,0.03)", borderRadius: "8px" }}>
            <div>
              <div style={{ fontSize: "13px", fontWeight: "500" }}>Auto-Escalate</div>
              <div style={{ fontSize: "11px", color: "#64748b" }}>Automatically escalate high/critical alerts</div>
            </div>
            <label style={{ position: "relative", display: "inline-block", width: "40px", height: "22px" }}>
              <input 
                type="checkbox" 
                checked={escalation.autoEscalate !== false}
                onChange={() => setEscalation({...escalation, autoEscalate: !escalation.autoEscalate})}
                style={{ opacity: 0, width: 0, height: 0 }}
              />
              <span style={{ 
                position: "absolute", 
                cursor: "pointer", 
                top: 0, 
                left: 0, 
                right: 0, 
                bottom: 0, 
                background: escalation.autoEscalate !== false ? "#38bdf8" : "#475569",
                borderRadius: "22px", 
                transition: "0.3s" 
              }}></span>
            </label>
          </div>

          <div>
            <label className="settings-label">Escalate After (minutes)</label>
            <input 
              type="number" 
              className="settings-input" 
              value={escalation.escalateAfter || 30}
              onChange={e => setEscalation({...escalation, escalateAfter: parseInt(e.target.value) || 30})}
              min="5"
              max="120"
            />
            <div className="settings-hint">Time before auto-escalation triggers</div>
          </div>

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 14px", background: "rgba(255,255,255,0.03)", borderRadius: "8px" }}>
            <div>
              <div style={{ fontSize: "13px", fontWeight: "500" }}>Critical Only</div>
              <div style={{ fontSize: "11px", color: "#64748b" }}>Only escalate CRITICAL severity alerts</div>
            </div>
            <label style={{ position: "relative", display: "inline-block", width: "40px", height: "22px" }}>
              <input 
                type="checkbox" 
                checked={escalation.criticalOnly || false}
                onChange={() => setEscalation({...escalation, criticalOnly: !escalation.criticalOnly})}
                style={{ opacity: 0, width: 0, height: 0 }}
              />
              <span style={{ 
                position: "absolute", 
                cursor: "pointer", 
                top: 0, 
                left: 0, 
                right: 0, 
                bottom: 0, 
                background: escalation.criticalOnly ? "#38bdf8" : "#475569",
                borderRadius: "22px", 
                transition: "0.3s" 
              }}></span>
            </label>
          </div>
        </div>
      </div>

      <div className="settings-card" style={{ background: "rgba(56,189,248,0.05)", border: "1px solid rgba(56,189,248,0.1)" }}>
        <h3 style={{ color: "#38bdf8", fontSize: "13px", fontWeight: "600", marginBottom: "8px" }}>
          <CheckCircle size={14} style={{ display: "inline", marginRight: "6px" }} /> Configuration Summary
        </h3>
        <div style={{ fontSize: "12px", color: "#64748b" }}>
          <div>📧 Email: {escalation.email || "❌ Not configured"}</div>
          <div>💬 WhatsApp: {escalation.whatsapp || "❌ Not configured"}</div>
          <div>📱 SMS: {escalation.sms || "❌ Not configured"}</div>
          <div>💬 Slack: {escalation.slack || "❌ Not configured"}</div>
          <div>📢 Teams: {escalation.teams || "❌ Not configured"}</div>
          <div>🚨 PagerDuty: {escalation.pagerduty || "❌ Not configured"}</div>
          <div style={{ marginTop: "8px", color: escalation.autoEscalate !== false ? "#22c55e" : "#ef4444" }}>
            ⚡ Auto-Escalate: {escalation.autoEscalate !== false ? "Enabled" : "Disabled"} · 
            {escalation.criticalOnly ? " CRITICAL only" : " All severity levels"} · 
            After {escalation.escalateAfter || 30} minutes
          </div>
        </div>
      </div>
    </div>
  );
}

// ==================== WORKSPACE TAB ====================

function WorkspaceTab({ config, setConfig }) {
  return (
    <div>
      <div className="settings-card">
        <h3 style={{ color: "#38bdf8", fontSize: "14px", fontWeight: "600", marginBottom: "12px" }}>
          <Cloud size={16} style={{ display: "inline", marginRight: "8px" }} /> Workspace Setup
        </h3>
        <p style={{ color: "#64748b", fontSize: "12px", marginBottom: "16px" }}>Configure your ClearSOC workspace and SIEM integration.</p>
        
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
          <div>
            <label className="settings-label">Workspace Name</label>
            <input 
              className="settings-input" 
              value={config.workspace?.name || "ClearSOC"} 
              onChange={e => setConfig({...config, workspace: {...config.workspace, name: e.target.value}})}
              placeholder="Enter workspace name"
            />
          </div>
          <div>
            <label className="settings-label">Region</label>
            <select 
              className="settings-select"
              value={config.workspace?.region || "local"}
              onChange={e => setConfig({...config, workspace: {...config.workspace, region: e.target.value}})}
            >
              <option value="local">Local (Self-Hosted)</option>
              <option value="aws">AWS us-east-1</option>
              <option value="azure">Azure East US</option>
              <option value="gcp">GCP us-central1</option>
            </select>
          </div>
        </div>

        <div style={{ marginTop: "16px" }}>
          <label className="settings-label">SIEM Platform</label>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: "8px", marginTop: "6px" }}>
            {["wazuh", "splunk", "elastic", "qradar"].map(t => (
              <div 
                key={t}
                onClick={() => setConfig({...config, siem: {...config.siem, type: t}})}
                style={{
                  padding: "12px",
                  borderRadius: "8px",
                  border: `2px solid ${config.siem?.type === t ? "#38bdf8" : "rgba(255,255,255,0.06)"}`,
                  background: config.siem?.type === t ? "rgba(56,189,248,0.08)" : "rgba(255,255,255,0.02)",
                  cursor: "pointer",
                  textAlign: "center"
                }}
              >
                <div style={{ fontSize: "13px", fontWeight: "600", color: config.siem?.type === t ? "#38bdf8" : "#64748b" }}>
                  {t.charAt(0).toUpperCase() + t.slice(1)}
                </div>
                {t === "wazuh" && <div style={{ fontSize: "10px", color: "#22c55e" }}>✓ Connected</div>}
                {t !== "wazuh" && <div style={{ fontSize: "10px", color: "#475569" }}>Coming soon</div>}
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="settings-card">
        <h3 style={{ color: "#38bdf8", fontSize: "14px", fontWeight: "600", marginBottom: "12px" }}>
          <FolderOpen size={16} style={{ display: "inline", marginRight: "8px" }} /> Log File Paths
        </h3>
        <div style={{ display: "grid", gap: "14px" }}>
          <div>
            <label className="settings-label">Alert Log Path</label>
            <input 
              className="settings-input" 
              value={config.siem?.alerts_path || "/var/ossec/logs/alerts/alerts.json"} 
              onChange={e => setConfig({...config, siem: {...config.siem, alerts_path: e.target.value}})}
              style={{ fontFamily: "monospace", fontSize: "12px" }}
            />
            <div className="settings-hint">Real-time alert log file</div>
          </div>
          <div>
            <label className="settings-label">Archives Path</label>
            <input 
              className="settings-input" 
              value={config.siem?.archives_path || "/var/ossec/logs/archives/"} 
              onChange={e => setConfig({...config, siem: {...config.siem, archives_path: e.target.value}})}
              style={{ fontFamily: "monospace", fontSize: "12px" }}
            />
            <div className="settings-hint">Historical logs directory</div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ==================== DATA SOURCES TAB ====================

function DataSourcesTab({ config, setConfig }) {
  const [sources, setSources] = useState([
    { id: 1, name: "Wazuh Alerts", type: "wazuh", status: "connected", path: "/var/ossec/logs/alerts/alerts.json" },
    { id: 2, name: "Wazuh Archives", type: "wazuh", status: "connected", path: "/var/ossec/logs/archives/" },
    { id: 3, name: "Suricata", type: "network", status: "disconnected", path: "/var/log/suricata/eve.json" },
    { id: 4, name: "Zeek", type: "network", status: "disconnected", path: "/var/log/zeek/" },
    { id: 5, name: "Sysmon", type: "endpoint", status: "connected", path: "EventLog/Microsoft-Windows-Sysmon/Operational" }
  ]);

  return (
    <div>
      <div className="settings-card">
        <h3 style={{ color: "#38bdf8", fontSize: "14px", fontWeight: "600", marginBottom: "12px" }}>
          <Database size={16} style={{ display: "inline", marginRight: "8px" }} /> Data Connectors
        </h3>
        <p style={{ color: "#64748b", fontSize: "12px", marginBottom: "16px" }}>Connect data sources to ingest security telemetry into ClearSOC.</p>
        
        {sources.map(source => (
          <div key={source.id} style={{ 
            display: "flex", 
            justifyContent: "space-between", 
            alignItems: "center", 
            padding: "12px 16px", 
            background: "rgba(255,255,255,0.03)", 
            border: "1px solid rgba(255,255,255,0.06)", 
            borderRadius: "8px",
            marginBottom: "8px"
          }}>
            <div>
              <div style={{ fontWeight: "500", fontSize: "13px" }}>
                {source.name}
                <span style={{ 
                  marginLeft: "8px", 
                  fontSize: "10px", 
                  padding: "2px 8px", 
                  borderRadius: "4px",
                  background: source.type === "wazuh" ? "rgba(56,189,248,0.15)" : 
                              source.type === "network" ? "rgba(249,115,22,0.15)" : 
                              "rgba(168,85,247,0.15)",
                  color: source.type === "wazuh" ? "#38bdf8" : 
                         source.type === "network" ? "#f97316" : "#a855f7"
                }}>
                  {source.type}
                </span>
              </div>
              <div style={{ fontSize: "11px", color: "#475569", fontFamily: "monospace" }}>{source.path}</div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
              <span style={{ 
                color: source.status === "connected" ? "#22c55e" : "#ef4444",
                fontSize: "12px",
                fontWeight: "600"
              }}>
                {source.status === "connected" ? "✅ Connected" : "⚠️ Disconnected"}
              </span>
              <button style={{ 
                background: "rgba(56,189,248,0.1)", 
                border: "1px solid rgba(56,189,248,0.2)", 
                color: "#38bdf8", 
                padding: "4px 12px", 
                borderRadius: "6px", 
                cursor: "pointer",
                fontSize: "11px"
              }}>
                Configure
              </button>
            </div>
          </div>
        ))}
        
        <button style={{ 
          marginTop: "12px",
          padding: "8px 16px",
          background: "transparent",
          border: "1px dashed rgba(56,189,248,0.3)",
          borderRadius: "8px",
          color: "#64748b",
          cursor: "pointer",
          fontSize: "13px",
          width: "100%"
        }}>
          <Plus size={14} style={{ display: "inline", marginRight: "6px" }} /> Add Data Connector
        </button>
      </div>
    </div>
  );
}

// ==================== DETECTION TAB ====================

function DetectionTab({ config, setConfig }) {
  const [rules, setRules] = useState([
    { id: 1, name: "Brute Force Attack", severity: "HIGH", enabled: true, mitre: "T1110" },
    { id: 2, name: "Malicious PowerShell", severity: "HIGH", enabled: true, mitre: "T1059.001" },
    { id: 3, name: "Privilege Escalation", severity: "CRITICAL", enabled: true, mitre: "T1078" },
    { id: 4, name: "LOLBins Execution", severity: "MEDIUM", enabled: true, mitre: "T1218" },
    { id: 5, name: "Credential Dumping", severity: "CRITICAL", enabled: false, mitre: "T1003" }
  ]);

  const sevColors = {
    CRITICAL: "#ef4444",
    HIGH: "#f97316", 
    MEDIUM: "#eab308",
    LOW: "#94a3b8"
  };

  return (
    <div>
      <div className="settings-card">
        <h3 style={{ color: "#38bdf8", fontSize: "14px", fontWeight: "600", marginBottom: "12px" }}>
          <Shield size={16} style={{ display: "inline", marginRight: "8px" }} /> Analytics Rules
        </h3>
        <p style={{ color: "#64748b", fontSize: "12px", marginBottom: "16px" }}>Enable or disable detection rules. ClearSOC will generate alerts based on enabled rules.</p>
        
        <div style={{ display: "grid", gap: "8px" }}>
          {rules.map(rule => (
            <div key={rule.id} style={{ 
              display: "flex", 
              justifyContent: "space-between", 
              alignItems: "center", 
              padding: "10px 14px", 
              background: "rgba(255,255,255,0.03)", 
              border: `1px solid ${rule.enabled ? "rgba(56,189,248,0.15)" : "rgba(255,255,255,0.04)"}`,
              borderRadius: "8px",
              opacity: rule.enabled ? 1 : 0.5
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                <input 
                  type="checkbox" 
                  checked={rule.enabled}
                  onChange={() => {
                    const updated = rules.map(r => 
                      r.id === rule.id ? {...r, enabled: !r.enabled} : r
                    );
                    setRules(updated);
                  }}
                  style={{ width: "16px", height: "16px", cursor: "pointer" }}
                />
                <div>
                  <div style={{ fontSize: "13px", fontWeight: "500" }}>{rule.name}</div>
                  <div style={{ fontSize: "11px", color: "#475569", fontFamily: "monospace" }}>{rule.mitre}</div>
                </div>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span style={{ 
                  padding: "2px 10px", 
                  borderRadius: "12px", 
                  fontSize: "10px",
                  fontWeight: "600",
                  background: `${sevColors[rule.severity]}20`,
                  color: sevColors[rule.severity]
                }}>
                  {rule.severity}
                </span>
                <button style={{ 
                  background: "transparent", 
                  border: "none", 
                  color: "#475569", 
                  cursor: "pointer" 
                }}>
                  <Edit2 size={14} />
                </button>
              </div>
            </div>
          ))}
        </div>
        
        <button style={{ 
          marginTop: "12px",
          padding: "8px 16px",
          background: "rgba(56,189,248,0.1)",
          border: "1px solid rgba(56,189,248,0.2)",
          borderRadius: "8px",
          color: "#38bdf8",
          cursor: "pointer",
          fontSize: "13px"
        }}>
          <Plus size={14} style={{ display: "inline", marginRight: "6px" }} /> Create Analytics Rule
        </button>
      </div>

      <div className="settings-card">
        <h3 style={{ color: "#38bdf8", fontSize: "14px", fontWeight: "600", marginBottom: "12px" }}>
          <BarChart size={16} style={{ display: "inline", marginRight: "8px" }} /> Detection Thresholds
        </h3>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "16px" }}>
          <div>
            <label className="settings-label">Brute Force Attempts</label>
            <input type="number" className="settings-input" value={config.thresholds?.brute_force_count || 5} 
              onChange={e => setConfig({...config, thresholds: {...config.thresholds, brute_force_count: parseInt(e.target.value)}})} />
            <div className="settings-hint">Failures within window</div>
          </div>
          <div>
            <label className="settings-label">Time Window</label>
            <input type="number" className="settings-input" value={config.thresholds?.brute_force_window_minutes || 5} 
              onChange={e => setConfig({...config, thresholds: {...config.thresholds, brute_force_window_minutes: parseInt(e.target.value)}})} />
            <div className="settings-hint">Minutes</div>
          </div>
          <div>
            <label className="settings-label">Min Rule Level</label>
            <input type="number" className="settings-input" value={config.thresholds?.min_rule_level || 3} 
              onChange={e => setConfig({...config, thresholds: {...config.thresholds, min_rule_level: parseInt(e.target.value)}})} />
            <div className="settings-hint">1-15</div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ==================== RETENTION TAB ====================

function RetentionTab({ config, setConfig }) {
  return (
    <div>
      <div className="settings-card">
        <h3 style={{ color: "#38bdf8", fontSize: "14px", fontWeight: "600", marginBottom: "12px" }}>
          <Clock size={16} style={{ display: "inline", marginRight: "8px" }} /> Data Retention
        </h3>
        <p style={{ color: "#64748b", fontSize: "12px", marginBottom: "16px" }}>Configure how long security data is retained in ClearSOC.</p>
        
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
          <div>
            <label className="settings-label">Alerts Retention</label>
            <select className="settings-select" value={config.retention?.alerts || "90d"}>
              <option value="30d">30 days</option>
              <option value="90d">90 days</option>
              <option value="180d">180 days</option>
              <option value="365d">365 days</option>
              <option value="forever">Forever</option>
            </select>
            <div className="settings-hint">How long to keep alert data</div>
          </div>
          <div>
            <label className="settings-label">Raw Logs Retention</label>
            <select className="settings-select" value={config.retention?.raw_logs || "30d"}>
              <option value="7d">7 days</option>
              <option value="30d">30 days</option>
              <option value="90d">90 days</option>
              <option value="180d">180 days</option>
            </select>
            <div className="settings-hint">How long to keep raw logs</div>
          </div>
        </div>
        
        <div style={{ marginTop: "16px", padding: "14px", background: "rgba(56,189,248,0.05)", border: "1px solid rgba(56,189,248,0.1)", borderRadius: "8px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <div style={{ fontSize: "12px", color: "#64748b" }}>Current Storage Usage</div>
              <div style={{ fontSize: "18px", fontWeight: "600", color: "#38bdf8" }}>2.4 GB</div>
            </div>
            <div>
              <div style={{ fontSize: "12px", color: "#64748b" }}>Total Events</div>
              <div style={{ fontSize: "18px", fontWeight: "600", color: "#e2e8f0" }}>1,492</div>
            </div>
            <div>
              <div style={{ fontSize: "12px", color: "#64748b" }}>Daily Ingestion</div>
              <div style={{ fontSize: "18px", fontWeight: "600", color: "#22c55e" }}>~45 events</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ==================== PERMISSIONS TAB ====================

function PermissionsTab({ config, setConfig }) {
  const [users, setUsers] = useState([
    { id: 1, name: "admin", email: "admin@clearsoc.local", role: "Admin", status: "active" },
    { id: 2, name: "soc-analyst", email: "analyst@clearsoc.local", role: "Analyst", status: "active" },
    { id: 3, name: "soc-lead", email: "lead@clearsoc.local", role: "Lead", status: "pending" }
  ]);

  return (
    <div>
      <div className="settings-card">
        <h3 style={{ color: "#38bdf8", fontSize: "14px", fontWeight: "600", marginBottom: "12px" }}>
          <Key size={16} style={{ display: "inline", marginRight: "8px" }} /> Access Control (RBAC)
        </h3>
        <p style={{ color: "#64748b", fontSize: "12px", marginBottom: "16px" }}>Manage users and their permissions in ClearSOC.</p>
        
        <div style={{ display: "grid", gap: "8px" }}>
          <div style={{ display: "grid", gridTemplateColumns: "2fr 2fr 1fr 1fr 1fr", gap: "8px", padding: "8px 12px", color: "#64748b", fontSize: "11px", fontWeight: "600" }}>
            <div>User</div>
            <div>Email</div>
            <div>Role</div>
            <div>Status</div>
            <div>Actions</div>
          </div>
          {users.map(user => (
            <div key={user.id} style={{ 
              display: "grid", 
              gridTemplateColumns: "2fr 2fr 1fr 1fr 1fr", 
              gap: "8px", 
              padding: "10px 12px", 
              background: "rgba(255,255,255,0.03)", 
              borderRadius: "6px",
              alignItems: "center"
            }}>
              <div style={{ fontWeight: "500", fontSize: "13px" }}>{user.name}</div>
              <div style={{ color: "#64748b", fontSize: "12px" }}>{user.email}</div>
              <div>
                <select className="settings-select" style={{ padding: "4px 8px", fontSize: "11px", width: "100%" }}>
                  <option value="Admin" selected={user.role === "Admin"}>Admin</option>
                  <option value="Lead" selected={user.role === "Lead"}>Lead</option>
                  <option value="Analyst" selected={user.role === "Analyst"}>Analyst</option>
                  <option value="Reader" selected={user.role === "Reader"}>Reader</option>
                </select>
              </div>
              <div>
                <span style={{ 
                  color: user.status === "active" ? "#22c55e" : "#eab308",
                  fontSize: "11px",
                  fontWeight: "600"
                }}>
                  {user.status === "active" ? "✅ Active" : "⏳ Pending"}
                </span>
              </div>
              <div>
                <button style={{ background: "transparent", border: "none", color: "#475569", cursor: "pointer" }}>
                  <Edit2 size={14} />
                </button>
                <button style={{ background: "transparent", border: "none", color: "#475569", cursor: "pointer", marginLeft: "6px" }}>
                  <Trash2 size={14} />
                </button>
              </div>
            </div>
          ))}
        </div>
        
        <button style={{ 
          marginTop: "12px",
          padding: "8px 16px",
          background: "rgba(56,189,248,0.1)",
          border: "1px solid rgba(56,189,248,0.2)",
          borderRadius: "8px",
          color: "#38bdf8",
          cursor: "pointer",
          fontSize: "13px"
        }}>
          <Plus size={14} style={{ display: "inline", marginRight: "6px" }} /> Add User
        </button>
      </div>
    </div>
  );
}

// ==================== AUTOMATION TAB ====================

function AutomationTab({ config, runPipeline, running, pipelineResult }) {
  return (
    <div>
      <div className="settings-card">
        <h3 style={{ color: "#38bdf8", fontSize: "14px", fontWeight: "600", marginBottom: "12px" }}>
          <Zap size={16} style={{ display: "inline", marginRight: "8px" }} /> Automation & Playbooks
        </h3>
        <p style={{ color: "#64748b", fontSize: "12px", marginBottom: "16px" }}>Configure automated responses and playbooks for incident response.</p>
        
        <div style={{ display: "grid", gap: "12px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 14px", background: "rgba(255,255,255,0.03)", borderRadius: "8px" }}>
            <div>
              <div style={{ fontSize: "13px", fontWeight: "500" }}>Auto-Close Resolved</div>
              <div style={{ fontSize: "11px", color: "#64748b" }}>Automatically close incidents after 7 days</div>
            </div>
            <label style={{ position: "relative", display: "inline-block", width: "40px", height: "22px" }}>
              <input type="checkbox" defaultChecked style={{ opacity: 0, width: 0, height: 0 }} />
              <span style={{ position: "absolute", cursor: "pointer", top: 0, left: 0, right: 0, bottom: 0, background: "#38bdf8", borderRadius: "22px", transition: "0.3s" }}></span>
            </label>
          </div>
          
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 14px", background: "rgba(255,255,255,0.03)", borderRadius: "8px" }}>
            <div>
              <div style={{ fontSize: "13px", fontWeight: "500" }}>Escalate Critical Alerts</div>
              <div style={{ fontSize: "11px", color: "#64748b" }}>Auto-escalate to L3 for CRITICAL severity</div>
            </div>
            <label style={{ position: "relative", display: "inline-block", width: "40px", height: "22px" }}>
              <input type="checkbox" defaultChecked style={{ opacity: 0, width: 0, height: 0 }} />
              <span style={{ position: "absolute", cursor: "pointer", top: 0, left: 0, right: 0, bottom: 0, background: "#38bdf8", borderRadius: "22px", transition: "0.3s" }}></span>
            </label>
          </div>
          
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 14px", background: "rgba(255,255,255,0.03)", borderRadius: "8px" }}>
            <div>
              <div style={{ fontSize: "13px", fontWeight: "500" }}>Run Pipeline Automatically</div>
              <div style={{ fontSize: "11px", color: "#64748b" }}>Auto-run pipeline every 5 minutes</div>
            </div>
            <label style={{ position: "relative", display: "inline-block", width: "40px", height: "22px" }}>
              <input type="checkbox" style={{ opacity: 0, width: 0, height: 0 }} />
              <span style={{ position: "absolute", cursor: "pointer", top: 0, left: 0, right: 0, bottom: 0, background: "#475569", borderRadius: "22px", transition: "0.3s" }}></span>
            </label>
          </div>
        </div>
      </div>
      
      <div className="settings-card">
        <h3 style={{ color: "#38bdf8", fontSize: "14px", fontWeight: "600", marginBottom: "12px" }}>
          <Play size={16} style={{ display: "inline", marginRight: "8px" }} /> Manual Pipeline Run
        </h3>
        <p style={{ color: "#64748b", fontSize: "12px", marginBottom: "16px" }}>Re-runs the detection and correlation pipeline against all events.</p>
        <button 
          onClick={runPipeline} 
          disabled={running}
          style={{
            display: "flex",
            alignItems: "center",
            gap: "8px",
            background: "rgba(34,197,94,0.15)",
            border: "1px solid rgba(34,197,94,0.3)",
            color: "#22c55e",
            padding: "10px 24px",
            borderRadius: "8px",
            cursor: running ? "not-allowed" : "pointer",
            fontSize: "13px",
            fontWeight: "600"
          }}
        >
          {running ? <><RefreshCw size={14} style={{ animation: "spin 1s linear infinite" }} /> Running...</> : <><Play size={14} /> Run Pipeline</>}
        </button>

        {pipelineResult && (
          <div style={{ 
            marginTop: "14px", 
            padding: "14px", 
            background: pipelineResult.status === "ok" ? "rgba(34,197,94,0.06)" : "rgba(239,68,68,0.06)",
            border: `1px solid ${pipelineResult.status === "ok" ? "rgba(34,197,94,0.2)" : "rgba(239,68,68,0.2)"}`,
            borderRadius: "8px"
          }}>
            <p style={{ color: pipelineResult.status === "ok" ? "#22c55e" : "#ef4444", fontWeight: "600", fontSize: "13px", margin: "0 0 6px" }}>
              {pipelineResult.status === "ok" ? "✅ Pipeline completed" : "❌ Pipeline failed"}
            </p>
            {pipelineResult.output && (
              <pre style={{ color: "#64748b", fontSize: "11px", margin: 0, whiteSpace: "pre-wrap", maxHeight: "150px", overflow: "auto" }}>
                {pipelineResult.output}
              </pre>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ==================== SYSTEM TAB ====================

function SystemTab({ config }) {
  const pipeline = config.pipeline || {};
  
  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: "12px", marginBottom: "16px" }}>
        <div className="settings-card" style={{ textAlign: "center" }}>
          <div style={{ color: "#64748b", fontSize: "11px" }}>Total Devices</div>
          <div style={{ color: "#38bdf8", fontSize: "24px", fontWeight: "700" }}>{pipeline.total_devices || 3}</div>
        </div>
        <div className="settings-card" style={{ textAlign: "center" }}>
          <div style={{ color: "#64748b", fontSize: "11px" }}>Active Incidents</div>
          <div style={{ color: "#f97316", fontSize: "24px", fontWeight: "700" }}>{pipeline.alerts_count || 9}</div>
        </div>
        <div className="settings-card" style={{ textAlign: "center" }}>
          <div style={{ color: "#64748b", fontSize: "11px" }}>Attack Chains</div>
          <div style={{ color: "#ef4444", fontSize: "24px", fontWeight: "700" }}>{pipeline.chains_count || 5}</div>
        </div>
        <div className="settings-card" style={{ textAlign: "center" }}>
          <div style={{ color: "#64748b", fontSize: "11px" }}>Zeek Status</div>
          <div style={{ color: "#22c55e", fontSize: "16px", fontWeight: "600" }}>🟢 LIVE</div>
        </div>
      </div>
      
      <div className="settings-card">
        <h3 style={{ color: "#38bdf8", fontSize: "14px", fontWeight: "600", marginBottom: "12px" }}>
          <Activity size={16} style={{ display: "inline", marginRight: "8px" }} /> System Status
        </h3>
        <div style={{ display: "grid", gap: "8px" }}>
          {[
            { label: "Wazuh Manager", status: "online", detail: "v4.14.4" },
            { label: "Windows Agent", status: "online", detail: "DESKTOP-G0LLA16" },
            { label: "API Server", status: "online", detail: "Port 8001" },
            { label: "Pipeline", status: "online", detail: "Last run: 4:41:30 PM" },
            { label: "Database", status: "online", detail: "1,492 events" }
          ].map(item => (
            <div key={item.label} style={{ display: "flex", justifyContent: "space-between", padding: "10px 14px", background: "rgba(255,255,255,0.03)", borderRadius: "6px" }}>
              <span style={{ fontSize: "13px" }}>{item.label}</span>
              <span style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span style={{ color: item.status === "online" ? "#22c55e" : "#ef4444", fontSize: "12px", fontWeight: "600" }}>
                  {item.status === "online" ? "✅ Online" : "❌ Offline"}
                </span>
                <span style={{ color: "#475569", fontSize: "11px" }}>{item.detail}</span>
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ==================== SAVE ICON ====================

function Save({ size }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z" />
      <polyline points="17 21 17 13 7 13 7 21" />
      <polyline points="7 3 7 8 15 8" />
    </svg>
  );
}
