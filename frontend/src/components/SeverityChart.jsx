import { PieChart, Pie, Cell, Tooltip } from "recharts";

const COLORS = {
  LOW: "#22c55e",
  MEDIUM: "#facc15",
  HIGH: "#ef4444",
};

export default function SeverityChart({ alerts }) {
  const data = ["LOW", "MEDIUM", "HIGH"].map((level) => ({
    name: level,
    value: alerts.filter((a) => a.severity === level).length,
  }));

  return (
    <div
      style={{
        border: "1px solid #333",
        padding: "16px",
        borderRadius: "8px",
        minHeight: "220px",
      }}
    >
      <h2 style={{ fontSize: "18px", marginBottom: "10px" }}>
        <span className="material-symbols-outlined">monitoring</span>
        Severity
      </h2>

      {alerts.length === 0 ? (
        <p style={{ color: "#888" }}>No data to visualize</p>
      ) : (
        <PieChart width={250} height={200}>
          <Pie data={data} dataKey="value" outerRadius={70}>
            {data.map((d) => (
              <Cell key={d.name} fill={COLORS[d.name]} />
            ))}
          </Pie>
          <Tooltip />
        </PieChart>
      )}
    </div>
  );
}
