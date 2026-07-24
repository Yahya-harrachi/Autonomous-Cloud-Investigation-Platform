import axios from 'axios';

// Use the backend URL directly (no proxy)
const API_BASE_URL = 'http://localhost:8000/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// ===== INCIDENT API =====
export const incidentAPI = {
  // Get all incidents from PostgreSQL
  getAll: async (skip = 0, limit = 100, status = null) => {
    let url = `/incidents/?skip=${skip}&limit=${limit}`;
    if (status && status !== 'all') {
      url += `&status=${status}`;
    }
    const response = await api.get(url);
    return response.data;
  },

  // Get a single incident by ID
  getById: async (id) => {
    const response = await api.get(`/incidents/${id}`);
    return response.data;
  },

  // Update incident status
  updateStatus: async (id, status) => {
    const response = await api.put(`/incidents/${id}/status?status=${status}`);
    return response.data;
  },

  // Update incident priority
  updatePriority: async (id, priority) => {
    const response = await api.put(`/incidents/${id}/priority?priority=${priority}`);
    return response.data;
  },

  // Delete incident
  delete: async (id) => {
    const response = await api.delete(`/incidents/${id}`);
    return response.data;
  },

  // Get incident statistics from PostgreSQL
  getStats: async () => {
    const response = await api.get('/incidents/stats');
    return response.data;
  },
};

export default api;