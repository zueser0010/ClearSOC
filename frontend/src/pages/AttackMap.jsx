import dashboard from "../data/dashboard_data.json";
import WorldAttackMap from "../components/WorldAttackMap";
import "../App.css";

export default function AttackMap() {
  const edges = dashboard.live_attack_map?.attack_edges || [];

  return (
    <div className="soc-page">
      <h1>Attack Map</h1>
      <div className="soc-panel">
        <WorldAttackMap />
      </div>

      <div className="soc-panel">
        <h2>Attack Edges</h2>
        <table className="soc-table">
          <thead>
            <tr><th>Source</th><th>Target</th><th>Type</th><th>Decision</th></tr>
          </thead>
          <tbody>
            {edges.map((e, i) => (
              <tr key={i}>
                <td>{e.source}</td>
                <td>{e.target}</td>
                <td>{e.attack_type}</td>
                <td>{e.decision}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
