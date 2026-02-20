import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { collaborationAPI } from '../services/api';

function NGODashboard() {
  const [collaborations, setCollaborations] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    location: '',
    start_date: '',
  });
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    fetchCollaborations();
  }, []);

  const fetchCollaborations = async () => {
    try {
      const response = await collaborationAPI.getCollaborations();
      setCollaborations(response.data);
      setLoading(false);
    } catch (err) {
      console.error('Failed to fetch collaborations', err);
      setLoading(false);
    }
  };

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await collaborationAPI.createCollaboration(formData);
      setShowForm(false);
      setFormData({ title: '', description: '', location: '', start_date: '' });
      fetchCollaborations();
    } catch (err) {
      alert('Failed to create collaboration');
    }
  };

  return (
    <div className="min-h-screen bg-gray-100" data-testid="ngo-dashboard-page">
      <header className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 py-4 sm:px-6 lg:px-8 flex justify-between items-center">
          <h1 className="text-2xl font-bold text-indigo-600" data-testid="ngo-title">NGO Dashboard</h1>
          <div className="flex gap-4">
            <button
              onClick={() => setShowForm(!showForm)}
              className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700"
              data-testid="create-collaboration-button"
            >
              + New Collaboration
            </button>
            <button
              onClick={() => navigate('/dashboard')}
              className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700"
              data-testid="back-to-dashboard-button"
            >
              ← Back to Dashboard
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-8 sm:px-6 lg:px-8">
        {showForm && (
          <div className="bg-white p-6 rounded-lg shadow mb-8" data-testid="collaboration-form">
            <h2 className="text-xl font-bold mb-4">Create New Collaboration</h2>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Title *
                </label>
                <input
                  type="text"
                  name="title"
                  value={formData.title}
                  onChange={handleChange}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                  required
                  data-testid="collaboration-title-input"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Description *
                </label>
                <textarea
                  name="description"
                  value={formData.description}
                  onChange={handleChange}
                  rows={4}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                  required
                  data-testid="collaboration-description-input"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Location
                </label>
                <input
                  type="text"
                  name="location"
                  value={formData.location}
                  onChange={handleChange}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                  data-testid="collaboration-location-input"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Start Date
                </label>
                <input
                  type="date"
                  name="start_date"
                  value={formData.start_date}
                  onChange={handleChange}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                  data-testid="collaboration-start-date-input"
                />
              </div>
              <div className="flex gap-4">
                <button
                  type="submit"
                  className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700"
                  data-testid="submit-collaboration-button"
                >
                  Create
                </button>
                <button
                  type="button"
                  onClick={() => setShowForm(false)}
                  className="px-4 py-2 bg-gray-300 text-gray-700 rounded-lg hover:bg-gray-400"
                  data-testid="cancel-collaboration-button"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        )}

        <div>
          <h2 className="text-xl font-bold mb-4">Your Collaborations</h2>
          {loading ? (
            <div className="text-center" data-testid="collaborations-loading">Loading...</div>
          ) : (
            <div className="space-y-4" data-testid="collaborations-list">
              {collaborations.length === 0 ? (
                <div className="bg-white p-8 rounded-lg shadow text-center text-gray-500" data-testid="no-collaborations-message">
                  No collaborations yet. Create your first one!
                </div>
              ) : (
                collaborations.map((collab) => (
                  <div key={collab.id} className="bg-white p-6 rounded-lg shadow" data-testid={`collaboration-${collab.id}`}>
                    <div className="flex justify-between items-start">
                      <div>
                        <h3 className="text-lg font-bold text-gray-800" data-testid={`collaboration-title-${collab.id}`}>{collab.title}</h3>
                        {collab.location && (
                          <p className="text-sm text-gray-600 mt-1" data-testid={`collaboration-location-${collab.id}`}>
                            📍 {collab.location}
                          </p>
                        )}
                        <p className="text-gray-700 mt-2" data-testid={`collaboration-description-${collab.id}`}>{collab.description}</p>
                        {collab.start_date && (
                          <p className="text-sm text-gray-600 mt-2" data-testid={`collaboration-start-date-${collab.id}`}>
                            <strong>Start Date:</strong> {new Date(collab.start_date).toLocaleDateString()}
                          </p>
                        )}
                      </div>
                      <span
                        className={`px-3 py-1 rounded-full text-sm font-semibold ${
                          collab.status === 'active' ? 'bg-green-100 text-green-800' :
                          collab.status === 'completed' ? 'bg-blue-100 text-blue-800' :
                          'bg-gray-100 text-gray-800'
                        }`}
                        data-testid={`collaboration-status-${collab.id}`}
                      >
                        {collab.status.toUpperCase()}
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

export default NGODashboard;