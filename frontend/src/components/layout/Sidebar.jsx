import { NavLink } from "react-router-dom";

const items = [
  {
    section: "SOC OVERVIEW",
    links: [
      { name: "Dashboard", path: "/" },
      { name: "Incidents", path: "/incidents", badge: 12 },
      { name: "Attack Chains", path: "/attack-chains" },
      { name: "Devices", path: "/devices" },
      { name: "Attack Map", path: "/attack-map" },
      { name: "Discover", path: "/discover" }
    ]
  },

  {
    section: "THREAT OPERATIONS",
    links: [
      { name: "Priority Queue", path: "/priority-queue", badge: 5 },
      { name: "Timeline View", path: "/timeline" },
      { name: "MITRE ATT&CK", path: "/mitre" },
      { name: "Threat Intelligence", path: "/threat-intel" },
      { name: "IOCs", path: "/iocs" },
      { name: "Cases", path: "/cases" },
      { name: "Playbooks", path: "/playbooks" }
    ]
  },

  {
    section: "SYSTEM",
    links: [
      { name: "Analytics", path: "/analytics" },
      { name: "Reports", path: "/reports" },
      { name: "Settings", path: "/settings" }
    ]
  }
];

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-top">
        <div className="sidebar-logo">
          <div className="logo-box">🛡</div>

          <div>
            <h2>ClearSOC</h2>
            <p>Security Operations Center</p>
            <span>v2.0.0</span>
          </div>
        </div>

        {items.map((group, index) => (
          <div key={index} className="sidebar-group">
            <p className="sidebar-section">
              {group.section}
            </p>

            {group.links.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  isActive
                    ? "sidebar-link active"
                    : "sidebar-link"
                }
              >
                <span>{item.name}</span>

                {item.badge && (
                  <span className="sidebar-badge">
                    {item.badge}
                  </span>
                )}
              </NavLink>
            ))}
          </div>
        ))}
      </div>

      <div className="sidebar-bottom">
        <h4>SYSTEM INFO</h4>

        <div className="system-row">
          <span>Total Devices</span>
          <strong>256</strong>
        </div>

        <div className="system-row">
          <span>Active Incidents</span>
          <strong>12</strong>
        </div>

        <div className="system-row">
          <span>Attack Chains</span>
          <strong>8</strong>
        </div>

        <div className="system-row">
          <span>Last Update</span>
          <strong>17:50:21</strong>
        </div>

        <div className="system-row">
          <span>Data Sources</span>
          <strong>12 / 12</strong>
        </div>

        <button className="report-btn">
          Generate Report
        </button>
      </div>
    </aside>
  );
}
