import { useEffect, useState } from "react";
import { getAlerts, getBlockedIPs } from "../services/api";
import AlertsTable from "../components/AlertsTable";
import BlockedIPs from "../components/BlockedIPs";
import SeverityChart from "../components/SeverityChart";

const REFRESH_INTERVAL = 5000; // 5 seconds

export default function Dashboard() {
  const [alerts, setAlerts] = useState([]);
  const [blocked, setBlocked] = useState([]);
  const [lastUpdated, setLastUpdated] = useState(null);

  const fetchData = async () => {
    try {
      const alertsRes = await getAlerts();
      const blockedRes = await getBlockedIPs();

      setAlerts(alertsRes.data);
      setBlocked(blockedRes.data);
      setLastUpdated(new Date());
    } catch (err) {
      console.error("Failed to fetch SOC data", err);
    }
  };

  useEffect(() => {
    // initial load
    fetchData();

    // auto-refresh
    const interval = setInterval(fetchData, REFRESH_INTERVAL);

    // cleanup (VERY IMPORTANT)
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="container">
      <div className="header">
        <div className="logo">
          <span className="material-symbols-outlined">security</span>
        </div>
        <div className="title">IDS Dashboard</div>

        <span className="badge">LIVE</span>

        {lastUpdated && (
          <span className="subtitle">
            Updated {lastUpdated.toLocaleTimeString()}
          </span>
        )}
      </div>

      <div className="grid">
        <div className="card pad severity">
          <SeverityChart alerts={alerts} />
        </div>

        <div className="card pad blocked">
          <BlockedIPs ips={blocked} />
        </div>

        <div className="card pad alerts">
          <AlertsTable alerts={alerts} />
        </div>
      </div>

      <div className="footer">
        Auto-refresh every {REFRESH_INTERVAL / 1000}s • SOC Live Feed
      </div>
    </div>
  );
}
