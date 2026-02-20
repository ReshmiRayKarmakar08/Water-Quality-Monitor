import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { authAPI, analyticsAPI, alertAPI } from '../services/api';
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

function Dashboard() {
  const [user, setUser] = useState(null);
  const [analytics, setAnalytics] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [userRes, analyticsRes, alertsRes] = await Promise.all([
        authAPI.getCurrentUser(),
        analyticsAPI.getAnalytics(),
        alertAPI.getAlerts(),
      ]);
      setUser(userRes.data);
      setAnalytics(analyticsRes.data);
      setAlerts(alertsRes.data);
      setLoading(false);
    } catch (err) {
      if (err.response?.status === 401) {
        navigate('/login');
      }
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    navigate('/login');
  };

  if (loading) {
    return <div className="flex items-center justify-center h-screen" data-testid="dashboard-loading">Loading dashboard...</div>;
  }

  return (
    <div className="min-h-screen bg-gray-100" data-testid="dashboard-page">
      {/* Header */}
      <header className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 py-4 sm:px-6 lg:px-8 flex justify-between items-center">
          <div>
            <h1 className="text-2xl font-bold text-blue-600" data-testid="dashboard-title">WaterWatch Dashboard</h1>
            <p className="text-sm text-gray-600" data-testid="user-info">Welcome, {user?.name} ({user?.role})</p>
          </div>
          <div className="flex gap-4">
            <button
              onClick={() => navigate('/map')}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              data-testid="map-view-button"
            >
              Map View
            </button>
            <button
              onClick={() => navigate('/reports/submit')}
              className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700"
              data-testid="submit-report-button"
            >
              Submit Report
            </button>
            {user?.role === 'authority' && (
              <button
                onClick={() => navigate('/authority')}
                className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700"
                data-testid="authority-dashboard-button"
              >
                Authority Panel
              </button>
            )}
            {user?.role === 'ngo' && (
              <button
                onClick={() => navigate('/ngo')}
                className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700"
                data-testid="ngo-dashboard-button"
              >
                NGO Panel
              </button>
            )}
            <button
              onClick={handleLogout}
              className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
              data-testid="logout-button"
            >
              Logout
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-8 sm:px-6 lg:px-8">
        {/* Alerts Section */}
        {alerts.length > 0 && (
          <div className="mb-8" data-testid="alerts-section">
            <h2 className="text-xl font-bold mb-4">Active Alerts</h2>
            <div className="space-y-2">
              {alerts.slice(0, 5).map((alert) => (
                <div
                  key={alert.id}
                  className={`p-4 rounded-lg ${
                    alert.severity === 'critical' ? 'bg-red-100 border-red-500' :
                    alert.severity === 'high' ? 'bg-orange-100 border-orange-500' :
                    'bg-yellow-100 border-yellow-500'
                  } border-l-4`}
                  data-testid={`alert-${alert.id}`}
                >
                  <p className="font-semibold">{alert.alert_type} Alert - {alert.severity}</p>
                  <p className="text-sm">{alert.message}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Overview Cards */}
        {analytics && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div className="bg-white p-6 rounded-lg shadow" data-testid="total-stations-card">
              <h3 className="text-gray-500 text-sm font-medium">Total Stations</h3>
              <p className="text-3xl font-bold text-blue-600" data-testid="total-stations-value">{analytics.overview.total_stations}</p>
            </div>
            <div className="bg-white p-6 rounded-lg shadow" data-testid="total-reports-card">
              <h3 className="text-gray-500 text-sm font-medium">Total Reports</h3>
              <p className="text-3xl font-bold text-green-600" data-testid="total-reports-value">{analytics.overview.total_reports}</p>
            </div>
            <div className="bg-white p-6 rounded-lg shadow" data-testid="pending-reports-card">
              <h3 className="text-gray-500 text-sm font-medium">Pending Reports</h3>
              <p className="text-3xl font-bold text-yellow-600" data-testid="pending-reports-value">{analytics.overview.pending_reports}</p>
            </div>
            <div className="bg-white p-6 rounded-lg shadow" data-testid="active-alerts-card">
              <h3 className="text-gray-500 text-sm font-medium">Active Alerts</h3>
              <p className="text-3xl font-bold text-red-600" data-testid="active-alerts-value">{analytics.overview.active_alerts}</p>
            </div>
          </div>
        )}

        {/* Charts */}
        {analytics && analytics.ph_trends.length > 0 && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
            {/* pH Trends */}
            <div className="bg-white p-6 rounded-lg shadow" data-testid="ph-trends-chart">
              <h3 className="text-lg font-bold mb-4">pH Trends (Last 30 Days)</h3>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={analytics.ph_trends}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="date" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Line type="monotone" dataKey="avg_ph" stroke="#3B82F6" name="Average pH" />
                </LineChart>
              </ResponsiveContainer>
            </div>

            {/* Station Comparisons */}
            <div className="bg-white p-6 rounded-lg shadow" data-testid="station-comparisons-chart">
              <h3 className="text-lg font-bold mb-4">Station Comparisons</h3>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={analytics.station_comparisons.slice(0, 5)}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="station" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Bar dataKey="avg_ph" fill="#3B82F6" name="Avg pH" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* Latest Averages */}
        {analytics && analytics.latest_averages && (
          <div className="bg-white p-6 rounded-lg shadow" data-testid="latest-averages-section">
            <h3 className="text-lg font-bold mb-4">Latest Water Quality Averages</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div data-testid="avg-ph-card">
                <p className="text-gray-500 text-sm">pH</p>
                <p className="text-2xl font-bold">{analytics.latest_averages.ph || 'N/A'}</p>
              </div>
              <div data-testid="avg-turbidity-card">
                <p className="text-gray-500 text-sm">Turbidity</p>
                <p className="text-2xl font-bold">{analytics.latest_averages.turbidity || 'N/A'}</p>
              </div>
              <div data-testid="avg-lead-card">
                <p className="text-gray-500 text-sm">Lead (mg/L)</p>
                <p className="text-2xl font-bold">{analytics.latest_averages.lead || 'N/A'}</p>
              </div>
              <div data-testid="avg-arsenic-card">
                <p className="text-gray-500 text-sm">Arsenic (mg/L)</p>
                <p className="text-2xl font-bold">{analytics.latest_averages.arsenic || 'N/A'}</p>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default Dashboard;