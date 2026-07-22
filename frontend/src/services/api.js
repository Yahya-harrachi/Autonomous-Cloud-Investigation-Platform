// API service for communicating with backend
import axios from 'axios';

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
    if (status) {
      url += `&status=${status}`;
    }
    const response = await api.get(url);
    return response.data;
  },

  // Get incident by ID
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

  // Assign incident
  assign: async (id, assignedTo, assignedTeam = null) => {
    const response = await api.post(`/incidents/${id}/assign`, null, {
      params: { assigned_to: assignedTo, assigned_team: assignedTeam }
    });
    return response.data;
  },

  // Delete incident
  delete: async (id) => {
    const response = await api.delete(`/incidents/${id}`);
    return response.data;
  },

  // Get incident stats
  getStats: async () => {
    const response = await api.get('/incidents/stats');
    return response.data;
  },

  // Get incidents from ingestion (memory)
  getFromIngestion: async () => {
    const response = await api.get('/ingestion/incidents');
    return response.data;
  },

  // Trigger ingestion
  runIngestion: async (count = 5) => {
    const response = await api.post(`/ingestion/run?count=${count}`);
    return response.data;
  },

  // Clear all (ingestion)
  clearIngestion: async () => {
    const response = await api.post('/ingestion/clear');
    return response.data;
  },

  // Get ingestion stats
  getIngestionStats: async () => {
    const response = await api.get('/ingestion/stats');
    return response.data;
  }
};

export default api;