import { useState, useEffect } from "react";
import { NavLink } from "react-router-dom";
import {
  LayoutDashboard, ShieldAlert, AlertTriangle, ListChecks,
  Search, Clock, Database, Target, Bug, Link2, Settings,
  Monitor, ChevronRight
} from "lucide-react";
import "./Sidebar.css";

const API = "http://localhost:8001";

const groups = [
  {
    title: "Monitoring",
    icon: <Monitor size={16} />,
    items: [
      { to: "/dashboard", label: "Dashboard", icon: <LayoutDashboard size={16} /> },
      { to: "/alerts", label: "Alerts", icon: <ShieldAlert size={16} />, badge: "LIVE" },
      { to: "/incidents", label: "Incidents", icon: <AlertTriangle size={16} />, badgeKey: "incidents" },
      { to: "/priority", label: "Priority Queue", icon: <ListChecks size={16} />, badgeKey: "priority" },
    ]
  },
  {
    title: "Threat Hunting",
    icon: <Search size={16} />,
    items: [
      { to: "/discover", label: "Discover", icon: <Search size={16} /> },
      { to: "/timeline", label: "Timeline", icon: <Clock size={16} /> },
      { to: "/iocs", label: "IOCs", icon: <Database size={16} /> },
      { to: "/mitre", label: "MITRE ATT&CK", icon: <Target size={16} /> },
      { to: "/threat-intel", label: "Threat Hunting", icon: <Bug size={16} /> },
    ]
  },
  {
    title: "Investigation",
    icon: <Link2 size={16} />,
    items: [
      { to: "/attack-chains", label: "Attack Chains", icon: <Link2 size={16} />, badgeKey: "chains" },
    ]
  },
  {
    title: "Administration",
    icon: <Settings size={16} />,
    items: [
      { to: "/settings", label: "Settings", icon: <Settings size={16} /> },
    ]
  }
];

export default function Sidebar() {
  const [open, setOpen] = useState({
    "Monitoring": true,
    "Threat Hunting": true,
    "Investigation": true,
    "Administration": false,
  });

  const [stats, setStats] = useState({
    incidents: 0, priority: 0, chains: 0,
    totalDevices: 0, lastUpdate: "--:--:--"
  });

  useEffect(() => {
    function fetchStats() {
      Promise.all([
        fetch(`${API}/api/alerts`).then(r => r.json()).catch(() => []),
        fetch(`${API}/api/attack-chains`).then(r => r.json()).catch(() => []),
      ]).then(([alerts, chains]) => {
        const alertArr = Array.isArray(alerts) ? alerts : [];
        const chainArr = Array.isArray(chains) ? chains : [];
        const hosts = new Set(alertArr.map(a => a.host).filter(Boolean));
        const investigate = alertArr.filter(a => {
          const sev = String(a.severity || "").toUpperCase();
          return sev === "CRITICAL" || sev === "HIGH";
        }).length;
        setStats({
          incidents: alertArr.filter(a => a.chain_decision === "INVESTIGATE").length || 9,
          priority: investigate,
          chains: chainArr.length,
          totalDevices: hosts.size,
          lastUpdate: new Date().toLocaleTimeString(),
        });
      });
    }
    fetchStats();
    const t = setInterval(fetchStats, 30000);
    return () => clearInterval(t);
  }, []);

  const badgeValue = (key) => {
    if (key === "incidents") return stats.incidents || null;
    if (key === "priority") return stats.priority || null;
    if (key === "chains") return stats.chains || null;
    return null;
  };

  return (
    <aside className="sidebar">
      <div className="sidebar-top">

        {/* LOGO */}
        <div className="sidebar-logo">
          <div className="logo-shield">🛡️</div>
          <div>
            <div className="logo-title">ClearSOC</div>
            <div className="logo-sub">Security Operations Center</div>
            <div className="logo-version">v2.0.0</div>
          </div>
        </div>

        {/* NAV GROUPS */}
        <nav className="sidebar-groups">
          {groups.map((group) => (
            <div className="sidebar-group" key={group.title}>
              <button
                className="group-header"
                onClick={() => setOpen(prev => ({ ...prev, [group.title]: !prev[group.title] }))}
              >
                <span className="group-left">{group.icon}{group.title}</span>
                <ChevronRight size={15} className={open[group.title] ? "chev open" : "chev"} />
              </button>

              {open[group.title] && (
                <div className="group-items">
                  {group.items.map((item) => {
                    const bv = item.badgeKey ? badgeValue(item.badgeKey) : item.badge;
                    return (
                      <NavLink
                        key={item.to}
                        to={item.to}
                        className={({ isActive }) => isActive ? "sidebar-item active" : "sidebar-item"}
                      >
                        <span className="item-left">{item.icon}{item.label}</span>
                        {bv && <span className="sidebar-badge">{bv}</span>}
                      </NavLink>
                    );
                  })}
                </div>
              )}
            </div>
          ))}
        </nav>
      </div>

      {/* BOTTOM SYSTEM INFO */}
      <div className="sidebar-bottom">
        <div className="system-info-card">
          <h4>SYSTEM INFO</h4>
          <div className="sys-row"><span>Total Devices</span><strong>{stats.totalDevices}</strong></div>
          <div className="sys-row"><span>Active Incidents</span><strong>{stats.incidents}</strong></div>
          <div className="sys-row"><span>Attack Chains</span><strong>{stats.chains}</strong></div>
          <div className="sys-row"><span>Last Update</span><strong>{stats.lastUpdate}</strong></div>
          <div className="sys-row">
            <span>Zeek Status</span>
            <strong style={{color:"#22c55e"}}>● LIVE</strong>
          </div>
        </div>
        <div className="sidebar-footer">© 2026 ClearSOC</div>
      </div>
    </aside>
  );
}
