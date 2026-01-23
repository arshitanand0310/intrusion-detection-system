import { useState } from "react";
import { unblockIP } from "../services/api";
import Toast from "./Toast";

export default function BlockedIPs({ ips, onRefresh }) {
  const [toast, setToast] = useState(null);

  const handleUnblock = async (ip) => {
    try {
      await unblockIP(ip);
      setToast({
        message: `IP ${ip} unblocked successfully`,
        type: "success",
      });
      if (onRefresh) onRefresh();
    } catch (err) {
      setToast({
        message: "Failed to unblock IP",
        type: "error",
      });
    }
  };

  return (
    <div className="card pad blocked">
      <h2>
        <span className="material-symbols-outlined danger">block</span>
        Blocked IPs
        <span className="badge">{ips.length}</span>
      </h2>

      {ips.length === 0 ? (
        <p className="empty">No IPs blocked</p>
      ) : (
        <ul className="blocked-list">
          {ips.map((item, i) => (
            <li key={i}>
              <div>
                <div className="blocked-ip">{item.ip_address}</div>
                <div className="blocked-reason">{item.reason}</div>
              </div>

              <button
                onClick={() => handleUnblock(item.ip_address)}
                style={{
                  background: "#22c55e",
                  color: "#000",
                  border: "none",
                  padding: "6px 10px",
                  borderRadius: "6px",
                  cursor: "pointer",
                  fontWeight: "600"
                }}
              >
                <span className="material-symbols-outlined success">
                  lock_open
                </span>
                Unblock
              </button>
            </li>
          ))}
        </ul>
      )}

      {toast && (
        <Toast
          message={toast.message}
          type={toast.type}
          onClose={() => setToast(null)}
        />
      )}
    </div>
  );
}
