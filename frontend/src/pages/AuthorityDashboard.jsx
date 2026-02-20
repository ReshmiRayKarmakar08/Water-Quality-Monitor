import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { reportAPI } from '../services/api';

function AuthorityDashboard() {
  const [reports, setReports] = useState([]);
  const [filter, setFilter] = useState('pending');
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    fetchReports();
  }, [filter]);

  const fetchReports = async () => {
    try {
      const response = await reportAPI.getReports(filter);
      setReports(response.data);
      setLoading(false);
    } catch (err) {
      console.error('Failed to fetch reports', err);
      setLoading(false);
    }
  };

  const handleVerify = async (id) => {
    try {
      await reportAPI.verifyReport(id);
      fetchReports();
    } catch (err) {
      alert('Failed to verify report');
    }
  };

  const handleReject = async (id) => {
    try {
      await reportAPI.rejectReport(id);
      fetchReports();
    } catch (err) {
      alert('Failed to reject report');
    }
  };

  return (
    <div className="min-h-screen bg-gray-100" data-testid="authority-dashboard-page">
      <header className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 py-4 sm:px-6 lg:px-8 flex justify-between items-center">
          <h1 className="text-2xl font-bold text-purple-600" data-testid="authority-title">Authority Dashboard</h1>
          <button
            onClick={() => navigate('/dashboard')}
            className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700"
            data-testid="back-to-dashboard-button"
          >
            ← Back to Dashboard
          </button>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-6">
          <h2 className="text-xl font-bold mb-4">Manage Reports</h2>
          <div className="flex gap-4">
            <button
              onClick={() => setFilter('pending')}
              className={`px-4 py-2 rounded-lg ${
                filter === 'pending' ? 'bg-yellow-600 text-white' : 'bg-white text-gray-700'
              }`}
              data-testid="filter-pending-button"
            >
              Pending
            </button>
            <button
              onClick={() => setFilter('verified')}
              className={`px-4 py-2 rounded-lg ${
                filter === 'verified' ? 'bg-green-600 text-white' : 'bg-white text-gray-700'
              }`}
              data-testid="filter-verified-button"
            >
              Verified
            </button>
            <button
              onClick={() => setFilter('rejected')}
              className={`px-4 py-2 rounded-lg ${
                filter === 'rejected' ? 'bg-red-600 text-white' : 'bg-white text-gray-700'
              }`}
              data-testid="filter-rejected-button"
            >
              Rejected
            </button>
          </div>
        </div>

        {loading ? (
          <div className="text-center" data-testid="reports-loading">Loading reports...</div>
        ) : (
          <div className="space-y-4" data-testid="reports-list">
            {reports.length === 0 ? (
              <div className="bg-white p-8 rounded-lg shadow text-center text-gray-500" data-testid="no-reports-message">
                No {filter} reports found
              </div>
            ) : (
              reports.map((report) => (
                <div key={report.id} className="bg-white p-6 rounded-lg shadow" data-testid={`report-${report.id}`}>
                  <div className="flex justify-between items-start">
                    <div className="flex-1">
                      <h3 className="text-lg font-bold text-gray-800" data-testid={`report-title-${report.id}`}>{report.title}</h3>
                      <p className="text-sm text-gray-600 mt-1" data-testid={`report-location-${report.id}`}>
                        📍 {report.location}
                      </p>
                      <p className="text-gray-700 mt-2" data-testid={`report-description-${report.id}`}>{report.description}</p>
                      {report.water_source && (
                        <p className="text-sm text-gray-600 mt-2" data-testid={`report-water-source-${report.id}`}>
                          <strong>Water Source:</strong> {report.water_source}
                        </p>
                      )}
                      {report.image_url && (
                        <img
                          src={report.image_url}
                          alt="Report"
                          className="mt-4 rounded-lg max-w-md"
                          data-testid={`report-image-${report.id}`}
                        />
                      )}
                      <p className="text-xs text-gray-500 mt-2" data-testid={`report-created-${report.id}`}>
                        Submitted: {new Date(report.created_at).toLocaleString()}
                      </p>
                    </div>
                    <div className="ml-4">
                      <span
                        className={`px-3 py-1 rounded-full text-sm font-semibold ${
                          report.status === 'pending' ? 'bg-yellow-100 text-yellow-800' :
                          report.status === 'verified' ? 'bg-green-100 text-green-800' :
                          'bg-red-100 text-red-800'
                        }`}
                        data-testid={`report-status-${report.id}`}
                      >
                        {report.status.toUpperCase()}
                      </span>
                    </div>
                  </div>
                  {report.status === 'pending' && (
                    <div className="flex gap-4 mt-4">
                      <button
                        onClick={() => handleVerify(report.id)}
                        className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700"
                        data-testid={`verify-button-${report.id}`}
                      >
                        ✓ Verify
                      </button>
                      <button
                        onClick={() => handleReject(report.id)}
                        className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
                        data-testid={`reject-button-${report.id}`}
                      >
                        ✗ Reject
                      </button>
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        )}
      </main>
    </div>
  );
}

export default AuthorityDashboard;