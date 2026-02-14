import { useEffect, useState } from "react";

function Reports() {
  const [reports, setReports] = useState([]);

  const fetchReports = () => {
    fetch("http://127.0.0.1:8000/reports")
      .then((res) => res.json())
      .then((data) => setReports(data))
      .catch((err) => console.error(err));
  };

  useEffect(() => {
    fetchReports();
  }, []);

  const updateStatus = async (id, status) => {
    const response = await fetch(
      `http://127.0.0.1:8000/reports/${id}?status=${status}`,
      {
        method: "PUT",
      }
    );

    if (response.ok) {
      fetchReports(); // reload reports
    } else {
      alert("Failed to update status");
    }
  };

  return (
    <div>
      <h2>View Reports (Authority)</h2>

      {reports.length === 0 ? (
        <p>No reports found</p>
      ) : (
        reports.map((report) => (
          <div key={report.id} style={{ border: "1px solid black", padding: "10px", marginBottom: "10px" }}>
            <h4>{report.title}</h4>
            <p>{report.description}</p>
            <p><b>Location:</b> {report.location}</p>
            <p><b>Status:</b> {report.status}</p>

            {report.status === "pending" && (
              <>
                <button onClick={() => updateStatus(report.id, "approved")}>
                  Verify
                </button>{" "}
                <button onClick={() => updateStatus(report.id, "rejected")}>
                  Reject
                </button>
              </>
            )}
          </div>
        ))
      )}
    </div>
  );
}

export default Reports;
