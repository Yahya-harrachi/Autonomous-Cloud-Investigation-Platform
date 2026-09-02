// frontend/src/components/incident/IncidentDetails.jsx
import React, { useState } from 'react';
import api from '../../services/api';

const IncidentDetails = ({ incident, onUpdate }) => {
  const [updating, setUpdating] = useState(false);
  const [status, setStatus] = useState(incident.status);
  const [priority, setPriority] = useState(incident.priority);
  const [assignedTo, setAssignedTo] = useState(incident.assigned_to || '');
  const [notes, setNotes] = useState('');

  const handleUpdate = async () => {
    setUpdating(true);
    try {
      await api.patch(`/incidents/${incident.id}`, {
        status,
        priority,
        assigned_to: assignedTo
      });
      onUpdate();
    } catch (error) {
      console.error('Error updating incident:', error);
    } finally {
      setUpdating(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Incident Information */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <h2 className="text-lg font-bold mb-4">📋 Incident Information</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700">Incident ID</label>
            <p className="mt-1 text-sm text-gray-900 font-mono">{incident.id}</p>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Created At</label>
            <p className="mt-1 text-sm text-gray-900">
              {new Date(incident.created_at).toLocaleString()}
            </p>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Source Type</label>
            <p className="mt-1 text-sm text-gray-900">{incident.source_type || 'N/A'}</p>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Source Event ID</label>
            <p className="mt-1 text-sm text-gray-900 font-mono">{incident.source_event_id || 'N/A'}</p>
          </div>
        </div>
      </div>

     

      {/* Incident Metadata */}
      {incident.extra_data && Object.keys(incident.extra_data).length > 0 && (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h2 className="text-lg font-bold mb-4">📊 Metadata</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {Object.entries(incident.extra_data).map(([key, value]) => (
              <div key={key}>
                <label className="block text-sm font-medium text-gray-700 capitalize">
                  {key.replace(/_/g, ' ')}
                </label>
                <p className="mt-1 text-sm text-gray-900">
                  {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default IncidentDetails;