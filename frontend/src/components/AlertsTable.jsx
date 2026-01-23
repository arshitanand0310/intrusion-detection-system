export default function AlertsTable({ alerts }) {
    return (
      <div className="card pad alerts">
        <h2>
          <span className="material-symbols-outlined alert">warning</span>
          Alerts
          <span className="badge">{alerts.length}</span>
        </h2>
  
        {alerts.length === 0 ? (
          <p className="empty">No alerts detected yet</p>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Attack</th>
                  <th>Attempts</th>
                  <th>Severity</th>
                </tr>
              </thead>
  
              <tbody>
                {alerts.map((a) => (
                  <tr key={a.id}>
                    <td>{a.ip_address}</td>
                    <td>{a.attack_type}</td>
                    <td>{a.attempts}</td>
                    <td>
                      <span
                        className={`pill ${
                          a.severity === "HIGH"
                            ? "high"
                            : a.severity === "MEDIUM"
                            ? "med"
                            : "low"
                        }`}
                      >
                        {a.severity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    );
  }
  