import React, { useEffect, useState } from "react";

const Alerts = () => {
  const [alertData, setAlertData] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("http://127.0.0.1:8000/alerts")
      .then((res) => res.json())
      .then((data) => {
        console.log("ALERTS FROM BACKEND:", data);
        setAlertData(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error("Error fetching alerts:", err);
        setLoading(false);
      });
  }, []);

  return (
    <div className="main-content">
      <div className="glass-card">
        <h2>System Alerts</h2>

        {loading ? (
          <p>Loading alerts...</p>
        ) : alertData.length === 0 ? (
          <p>No alerts available</p>
        ) : (
          <table className="custom-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Message</th>
                <th>Location</th>
                <th>Issued At</th>
              </tr>
            </thead>
            <tbody>
              {alertData.map((alert) => (
                <tr key={alert.id} className="alert-row">
                  <td>
                    <span className="badge-danger">
                      {alert.type}
                    </span>
                  </td>
                  <td>{alert.message}</td>
                  <td>{alert.location}</td>
                  <td>
                    {new Date(alert.issued_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

export default Alerts;
