// frontend/src/pages/IncidentDetail.jsx
import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import EvidenceSection from '../components/evidence/EvidenceSection';
import TimelineSection from '../components/evidence/TimelineSection';
import IncidentDetails from '../components/incident/IncidentDetails';
import api from '../services/api';

const IncidentDetail = () => {
  const { id } = useParams();
  const [incident, setIncident] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('details');
  const [updating, setUpdating] = useState(false);

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
      console.error('Error loading incident:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleStatusUpdate = async (newStatus) => {
  setUpdating(true);
  try {
    console.log(`📤 Updating status to: ${newStatus}`);
    
    // ✅ Use PUT with /status endpoint
    const response = await api.put(`/incidents/${incident.id}/status`, null, {
      params: { status: newStatus }
    });
    
    console.log('📥 Response:', response.data);
    setIncident(response.data);
    await loadIncident();
    
  } catch (err) {
    console.error('❌ Error updating status:', err);
    alert('Failed to update status: ' + (err.response?.data?.detail || err.message));
  } finally {
    setUpdating(false);
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

  const statusOptions = ['pending', 'investigating', 'completed', 'resolved'];

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Incident Header */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-6">
        <div className="flex items-start justify-between flex-wrap gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center space-x-3 flex-wrap gap-2">
              <h1 className="text-2xl font-bold text-gray-900 truncate">{incident.title}</h1>
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
            </div>
          </div>
          
          {/* ✅ Only Update Status button - Remove Assign */}
          <div className="flex space-x-2 flex-wrap gap-2">
            <div className="relative">
              <select
                value={incident.status}
                onChange={(e) => handleStatusUpdate(e.target.value)}
                disabled={updating}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm border-none appearance-none cursor-pointer disabled:opacity-50"
              >
                {statusOptions.map((status) => (
                  <option key={status} value={status} className="text-gray-900 bg-white">
                    {status === 'pending' ? '⏳ Pending' :
                     status === 'investigating' ? '🔍 Investigating' :
                     status === 'completed' ? '✅ Completed' :
                     '🔒 Resolved'}
                  </option>
                ))}
              </select>
              <span className="absolute right-2 top-1/2 transform -translate-y-1/2 text-white pointer-events-none">
                ▼
              </span>
            </div>
          </div>
        </div>

        {/* Description */}
        <div className="mt-4 p-4 bg-gray-50 rounded-lg">
          <p className="text-gray-700 whitespace-pre-wrap">{incident.description}</p>
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
        <nav className="flex space-x-8 overflow-x-auto">
          <button
            onClick={() => setActiveTab('details')}
            className={`py-2 px-1 border-b-2 text-sm font-medium whitespace-nowrap ${
              activeTab === 'details'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            📋 Details
          </button>
          <button
            onClick={() => setActiveTab('evidence')}
            className={`py-2 px-1 border-b-2 text-sm font-medium whitespace-nowrap ${
              activeTab === 'evidence'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            📊 Evidence {incident.evidence_count > 0 && `(${incident.evidence_count})`}
          </button>
          <button
            onClick={() => setActiveTab('timeline')}
            className={`py-2 px-1 border-b-2 text-sm font-medium whitespace-nowrap ${
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
          <IncidentDetails incident={incident} onUpdate={loadIncident} />
        )}

        {activeTab === 'evidence' && (
          <EvidenceSection incidentId={id} />
        )}

        {activeTab === 'timeline' && (
          <TimelineSection incidentId={id} />
        )}
      </div>
    </div>
  );
};

export default IncidentDetail;