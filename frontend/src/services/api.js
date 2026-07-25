import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// ===== INCIDENT API (Database) =====
export const incidentAPI = {
  getAll: async (skip = 0, limit = 100, status = null) => {
    let url = `/incidents/?skip=${skip}&limit=${limit}`;
    if (status && status !== 'all') {
      url += `&status=${status}`;
    }
    const response = await api.get(url);
    return response.data;
  },
  getById: async (id) => {
    const response = await api.get(`/incidents/${id}`);
    return response.data;
  },
  updateStatus: async (id, status) => {
    const response = await api.put(`/incidents/${id}/status?status=${status}`);
    return response.data;
  },
  delete: async (id) => {
    const response = await api.delete(`/incidents/${id}`);
    return response.data;
  },
  getStats: async () => {
    const response = await api.get('/incidents/stats');
    return response.data;
  },
};

// ===== DEBUG API (CloudTrail Events - Raw) =====
export const debugAPI = {
  // Get CloudTrail events
  getCloudTrailEvents: async (count = 50, eventName = null, username = null, hoursBack = 24) => {
    let url = `/debug/cloudtrail/events?count=${count}&hours_back=${hoursBack}`;
    if (eventName) {
      url += `&event_name=${encodeURIComponent(eventName)}`;
    }
    if (username) {
      url += `&username=${encodeURIComponent(username)}`;
    }
    const response = await api.get(url);
    return response.data;
  },
  
  // Check CloudTrail health
  checkCloudTrailHealth: async () => {
    const response = await api.get('/debug/cloudtrail/health');
    return response.data;
  },
};

export default api;