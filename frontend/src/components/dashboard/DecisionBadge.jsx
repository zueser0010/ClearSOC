export default function DecisionBadge({ value }) {
  const decision = String(value || "CLEAR").toUpperCase();

  const colors = {
    ESCALATE: "badge-critical",
    INVESTIGATE: "badge-high",
    MONITOR: "badge-medium",
    CLEAR: "badge-low"
  };

  return (
    <span className={`badge ${colors[decision] || "badge-low"}`}>
      {decision}
    </span>
  );
}
