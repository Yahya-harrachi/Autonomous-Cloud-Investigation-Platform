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
  // Get all incidents
  getAll: async (skip = 0, limit = 100, status = null) => {
    let url = `/incidents/?skip=${skip}&limit=${limit}`;
    if (status && status !== 'all') {
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
};

// ===== DEBUG API (CloudTrail Events - Raw) =====
export const debugAPI = {
  // Get CloudTrail events
  getCloudTrailEvents: async (count = 50, eventName = null, username = null, hoursBack = 24) => {
    let url = `/debug/cloudtrail/normalized?count=${count}&hours_back=${hoursBack}`;
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
    const response = await api.get('/debug/cloudtrail/normalized/health');
    return response.data;
  },
};

// ===== RULE API =====
export const ruleAPI = {
  // Get all rules
  getAll: async (enabledOnly = false, ruleType = null) => {
    let url = `/rules/?enabled_only=${enabledOnly}`;
    if (ruleType) {
      url += `&rule_type=${ruleType}`;
    }
    const response = await api.get(url);
    return response.data;
  },

  // Get a single rule
  getById: async (id) => {
    const response = await api.get(`/rules/${id}`);
    return response.data;
  },

  // Create a rule
  create: async (data) => {
    const response = await api.post('/rules/', data);
    return response.data;
  },

  // Update a rule
  update: async (id, data) => {
    const response = await api.put(`/rules/${id}`, data);
    return response.data;
  },

  // Delete a rule
  delete: async (id) => {
    const response = await api.delete(`/rules/${id}`);
    return response.data;
  },

  // Enable a rule
  enable: async (id) => {
    const response = await api.patch(`/rules/${id}/enable`);
    return response.data;
  },

  // Disable a rule
  disable: async (id) => {
    const response = await api.patch(`/rules/${id}/disable`);
    return response.data;
  },

  // Test a rule
  test: async (rule, eventData) => {
    const response = await api.post('/rules/test', {
      rule: rule,
      event_data: eventData,
    });
    return response.data;
  },

  // Get rule types
  getTypes: async () => {
    const response = await api.get('/rules/types');
    return response.data;
  },
};

export default api;