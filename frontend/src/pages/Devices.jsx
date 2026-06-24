import dashboard from "../data/dashboard_data.json";
import "../App.css";

export default function Devices() {
  const devices = dashboard.devices || [];

  return (
    <div className="page">
      <h1>Devices</h1>
      <section className="panel">
        <table>
          <thead>
            <tr>
              <th>Host</th>
              <th>Risk Score</th>
              <th>Risk Level</th>
              <th>Incidents</th>
              <th>Attack Chains</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d, index) => (
              <tr key={index}>
                <td>{d.host || "N/A"}</td>
                <td>{d.risk_score || 0}</td>
                <td>{d.risk_level || "N/A"}</td>
                <td>{d.incidents || 0}</td>
                <td>{d.attack_chains || 0}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
