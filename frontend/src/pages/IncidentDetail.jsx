// frontend/src/pages/IncidentDetail.jsx
import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import EvidenceSection from '../components/evidence/EvidenceSection';
import api from '../services/api';

const IncidentDetail = () => {
  const { id } = useParams();
  const [incident, setIncident] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('details');

  useEffect(() => {
    loadIncident();
  }, [id]);

  const loadIncident = async () => {
    setLoading(true);
    try {
      const response = await api.get(`/incidents/${id}`);
      setIncident(response.data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-3 text-gray-600">Loading incident...</p>
        </div>
      </div>
    );
  }

  if (error || !incident) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-center">
          <div className="text-4xl mb-2">❌</div>
          <h2 className="text-xl font-bold text-red-700">Error loading incident</h2>
          <p className="text-red-600">{error || 'Incident not found'}</p>
        </div>
      </div>
    );
  }

  const getPriorityColor = (priority) => {
    const colors = {
      'CRITICAL': 'bg-red-100 text-red-800',
      'HIGH': 'bg-orange-100 text-orange-800',
      'MEDIUM': 'bg-yellow-100 text-yellow-800',
      'LOW': 'bg-blue-100 text-blue-800'
    };
    return colors[priority] || 'bg-gray-100 text-gray-800';
  };

  const getStatusColor = (status) => {
    const colors = {
      'PENDING': 'bg-yellow-100 text-yellow-800',
      'INVESTIGATING': 'bg-blue-100 text-blue-800',
      'COMPLETED': 'bg-green-100 text-green-800',
      'RESOLVED': 'bg-purple-100 text-purple-800'
    };
    return colors[status] || 'bg-gray-100 text-gray-800';
  };

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Incident Header */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-6">
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center space-x-3">
              <h1 className="text-2xl font-bold text-gray-900">{incident.title}</h1>
              <span className={`px-2 py-1 text-xs rounded-full ${getPriorityColor(incident.priority)}`}>
                {incident.priority}
              </span>
              <span className={`px-2 py-1 text-xs rounded-full ${getStatusColor(incident.status)}`}>
                {incident.status}
              </span>
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-gray-500">
              <span>🆔 {incident.id}</span>
              <span>•</span>
              <span>📅 {new Date(incident.created_at).toLocaleString()}</span>
              {incident.assigned_to && (
                <>
                  <span>•</span>
                  <span>👤 Assigned to: {incident.assigned_to}</span>
                </>
              )}
            </div>
          </div>
          <div className="flex space-x-2">
            <button className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm">
              Update Status
            </button>
            <button className="px-4 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 text-sm">
              Assign
            </button>
          </div>
        </div>

        {/* Description */}
        <div className="mt-4 p-4 bg-gray-50 rounded-lg">
          <p className="text-gray-700">{incident.description}</p>
        </div>

        {/* Tags */}
        {incident.tags && incident.tags.length > 0 && (
          <div className="mt-4 flex flex-wrap gap-2">
            {incident.tags.map((tag, idx) => (
              <span key={idx} className="px-2 py-1 bg-gray-100 text-gray-600 text-xs rounded">
                #{tag}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200 mb-6">
        <nav className="flex space-x-8">
          <button
            onClick={() => setActiveTab('details')}
            className={`py-2 px-1 border-b-2 text-sm font-medium ${
              activeTab === 'details'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            📋 Details
          </button>
          <button
            onClick={() => setActiveTab('evidence')}
            className={`py-2 px-1 border-b-2 text-sm font-medium ${
              activeTab === 'evidence'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            📊 Evidence {incident.evidence_count > 0 && `(${incident.evidence_count})`}
          </button>
          <button
            onClick={() => setActiveTab('timeline')}
            className={`py-2 px-1 border-b-2 text-sm font-medium ${
              activeTab === 'timeline'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            🕐 Timeline
          </button>
        </nav>
      </div>

      {/* Tab Content */}
      <div>
        {activeTab === 'details' && (
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <h2 className="text-lg font-bold mb-4">Incident Details</h2>
            {/* Add more details here */}
          </div>
        )}

        {activeTab === 'evidence' && (
          <EvidenceSection incidentId={id} />
        )}

        {activeTab === 'timeline' && (
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <h2 className="text-lg font-bold mb-4">Timeline</h2>
            <p className="text-gray-500">Timeline view coming soon...</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default IncidentDetail;