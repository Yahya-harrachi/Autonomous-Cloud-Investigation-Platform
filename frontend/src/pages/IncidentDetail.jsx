import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { incidentAPI } from '../services/api';
import StatusBadge from '../components/StatusBadge';
import SeverityBadge from '../components/SeverityBadge';

const IncidentDetail = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [incident, setIncident] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [updating, setUpdating] = useState(false);

  useEffect(() => {
    loadIncident();
  }, [id]);

  const loadIncident = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await incidentAPI.getById(id);
      setIncident(data);
    } catch (err) {
      console.error('Error loading incident:', err);
      setError('Incident not found');
    } finally {
      setLoading(false);
    }
  };

  const handleStatusUpdate = async (newStatus) => {
    setUpdating(true);
    try {
      await incidentAPI.updateStatus(id, newStatus);
      await loadIncident();
    } catch (err) {
      console.error('Error updating status:', err);
    } finally {
      setUpdating(false);
    }
  };

  const handleDelete = async () => {
    if (window.confirm('Are you sure you want to delete this incident?')) {
      try {
        await incidentAPI.delete(id);
        navigate('/incidents');
      } catch (err) {
        console.error('Error deleting incident:', err);
      }
    }
  };

  if (loading) {
    return <div className="text-center py-8">Loading incident...</div>;
  }

  if (error || !incident) {
    return <div className="text-center py-8 text-red-500">Incident not found</div>;
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-4xl">
      <div className="bg-white rounded-lg shadow">
        {/* Header */}
        <div className="px-6 py-4 border-b border-gray-200 flex justify-between items-start">
          <div>
            <h1 className="text-2xl font-bold">{incident.title}</h1>
            <div className="flex items-center space-x-4 mt-2">
              <SeverityBadge severity={incident.priority?.toUpperCase() || 'MEDIUM'} />
              <StatusBadge status={incident.status || 'pending'} />
              <span className="text-sm text-gray-500">
                Created: {new Date(incident.created_at).toLocaleString()}
              </span>
            </div>
          </div>
          <button
            onClick={handleDelete}
            className="text-red-600 hover:text-red-800"
          >
            Delete
          </button>
        </div>

        {/* Body */}
        <div className="px-6 py-4 space-y-6">
          {/* Description */}
          <div>
            <h3 className="text-sm font-medium text-gray-500">Description</h3>
            <p className="mt-1 text-gray-900">{incident.description || 'No description provided.'}</p>
          </div>

          {/* Source Info */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <h3 className="text-sm font-medium text-gray-500">Source Type</h3>
              <p className="mt-1">{incident.source_type || 'N/A'}</p>
            </div>
            <div>
              <h3 className="text-sm font-medium text-gray-500">Source Event ID</h3>
              <p className="mt-1 text-sm text-gray-600">{incident.source_event_id || 'N/A'}</p>
            </div>
          </div>

          {/* Extra Data */}
          {incident.extra_data && Object.keys(incident.extra_data).length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-gray-500">Additional Data</h3>
              <pre className="mt-1 bg-gray-50 p-3 rounded-md text-sm overflow-auto">
                {JSON.stringify(incident.extra_data, null, 2)}
              </pre>
            </div>
          )}

          {/* Tags */}
          {incident.tags && incident.tags.length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-gray-500">Tags</h3>
              <div className="mt-1 flex flex-wrap gap-2">
                {incident.tags.map((tag) => (
                  <span key={tag} className="px-2 py-1 bg-gray-100 rounded-md text-xs">
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Status Update */}
          <div className="border-t border-gray-200 pt-4">
            <h3 className="text-sm font-medium text-gray-500 mb-2">Update Status</h3>
            <div className="flex space-x-2">
              {['pending', 'investigating', 'completed', 'resolved'].map((s) => (
                <button
                  key={s}
                  onClick={() => handleStatusUpdate(s)}
                  disabled={updating || incident.status === s}
                  className={`px-3 py-1 rounded-md text-sm ${
                    incident.status === s
                      ? 'bg-gray-800 text-white'
                      : 'bg-gray-200 hover:bg-gray-300'
                  } ${updating ? 'opacity-50' : ''}`}
                >
                  {s.charAt(0).toUpperCase() + s.slice(1)}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default IncidentDetail;