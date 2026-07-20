// API service for communicating with backend
import axios from 'axios';

// Detect if running in Docker or local
const isDocker = process.env.REACT_APP_DOCKER === 'true';
const API_BASE_URL = isDocker 
  ? '/api'  // In Docker, use nginx proxy
  : 'http://localhost:8000/api';  // Local development

// Create axios instance
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Incident API calls
export const incidentAPI = {
  // Get all incidents
  getAll: async () => {
    const response = await api.get('/incidents/');
    return response.data;
  },

  // Get single incident
  getById: async (id) => {
    const response = await api.get(`/incidents/${id}`);
    return response.data;
  },

  // Create incident
  create: async (data) => {
    const response = await api.post('/incidents/', data);
    return response.data;
  },

  // Update incident
  update: async (id, data) => {
    const response = await api.put(`/incidents/${id}`, data);
    return response.data;
  },

  // Update status
  updateStatus: async (id, status) => {
    const response = await api.put(`/incidents/${id}/status?status=${status}`);
    return response.data;
  },

  // Delete incident
  delete: async (id) => {
    const response = await api.delete(`/incidents/${id}`);
    return response.data;
  },

  // Upload evidence
  uploadEvidence: async (incidentId, file) => {
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await axios.post(
      `${API_BASE_URL}/incidents/${incidentId}/evidence`,
      formData,
      {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      }
    );
    return response.data;
  },

  // List evidence
  listEvidence: async (incidentId) => {
    const response = await api.get(`/incidents/${incidentId}/evidence`);
    return response.data;
  },

  // Delete evidence
  deleteEvidence: async (incidentId, filename) => {
    const response = await api.delete(`/incidents/${incidentId}/evidence/${filename}`);
    return response.data;
  },
};

export default api;