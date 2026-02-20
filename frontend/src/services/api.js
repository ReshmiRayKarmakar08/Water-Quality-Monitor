import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add token to requests
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Auth APIs
export const authAPI = {
  register: (data) => api.post('/api/auth/register', data),
  login: (data) => api.post('/api/auth/login', data),
  getCurrentUser: () => api.get('/api/auth/me'),
};

// Station APIs
export const stationAPI = {
  getStations: () => api.get('/api/stations'),
  getReadings: () => api.get('/api/readings'),
};

// Report APIs
export const reportAPI = {
  createReport: (data) => api.post('/api/reports', data),
  getReports: (status) => api.get('/api/reports', { params: { status } }),
  verifyReport: (id) => api.put(`/api/reports/${id}/verify`),
  rejectReport: (id) => api.put(`/api/reports/${id}/reject`),
};

// Alert APIs
export const alertAPI = {
  getAlerts: () => api.get('/api/alerts'),
  createAlert: (data) => api.post('/api/alerts', data),
  markAsRead: (id) => api.put(`/api/alerts/${id}/read`),
};

// Analytics APIs
export const analyticsAPI = {
  getAnalytics: () => api.get('/api/analytics'),
};

// Collaboration APIs
export const collaborationAPI = {
  createCollaboration: (data) => api.post('/api/collaborations', data),
  getCollaborations: () => api.get('/api/collaborations'),
  updateStatus: (id, status) => api.put(`/api/collaborations/${id}/status`, { new_status: status }),
};

export default api;