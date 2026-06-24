export default function SeverityBadge({ value }) {
  const severity = String(value || "LOW").toUpperCase();

  const colors = {
    CRITICAL: "badge-critical",
    HIGH: "badge-high",
    MEDIUM: "badge-medium",
    LOW: "badge-low"
  };

  return (
    <span className={`badge ${colors[severity] || "badge-low"}`}>
      {severity}
    </span>
  );
}
