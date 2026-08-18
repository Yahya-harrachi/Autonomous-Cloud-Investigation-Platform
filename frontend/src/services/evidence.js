// frontend/src/services/evidence.js
import api from './api';

/**
 * Get evidence artifacts for an incident
 * @param {string} incidentId - The incident ID
 * @returns {Promise} List of evidence artifacts
 */
export const getIncidentEvidence = async (incidentId) => {
  try {
    const response = await api.get(`/incidents/${incidentId}/evidence`);
    return response.data;
  } catch (error) {
    console.error('Error fetching evidence:', error);
    throw error;
  }
};

/**
 * Verify evidence integrity
 * @param {string} artifactId - The artifact ID
 * @returns {Promise} Verification result
 */
export const verifyEvidence = async (artifactId) => {
  try {
    // Try the incidents router endpoint first (most likely to work)
    const response = await api.post(`/incidents/evidence/${artifactId}/verify`);
    return response.data;
  } catch (error) {
    // If that fails, try the evidence router endpoint
    try {
      const response = await api.post(`/evidence/${artifactId}/verify`);
      return response.data;
    } catch (secondError) {
      console.error('Error verifying evidence:', secondError);
      throw secondError;
    }
  }
};

/**
 * Download evidence
 * @param {string} artifactId - The artifact ID
 * @returns {Promise} Download URL
 */
export const downloadEvidence = async (artifactId) => {
  try {
    const response = await api.get(`/evidence/${artifactId}/download`);
    return response.data;
  } catch (error) {
    console.error('Error downloading evidence:', error);
    throw error;
  }
};

/**
 * Batch verify all evidence for an incident
 * @param {string} incidentId - The incident ID
 * @returns {Promise} Batch verification results
 */
export const batchVerifyEvidence = async (incidentId) => {
  try {
    const response = await api.post(`/incidents/${incidentId}/evidence/verify-all`);
    return response.data;
  } catch (error) {
    console.error('Error batch verifying evidence:', error);
    throw error;
  }
};