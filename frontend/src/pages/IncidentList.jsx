import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { incidentAPI } from '../services/api';
import StatusBadge from '../components/StatusBadge';
import SeverityBadge from '../components/SeverityBadge';
import websocketService from '../services/websocket';

const IncidentList = () => {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const [stats, setStats] = useState({});

  useEffect(() => {
    loadData();
    
    // Listen for new incidents via WebSocket
    const onNewIncident = (incident) => {
      console.log('🚨 New incident received:', incident);
      setIncidents(prev => [incident, ...prev]);
      setStats(prev => ({
        ...prev,
        total: (prev.total || 0) + 1,
        pending: (prev.pending || 0) + 1,
      }));
    };
    
    websocketService.on('new_incident', onNewIncident);
    
    return () => {
      websocketService.off('new_incident', onNewIncident);
    };
  }, [filter]);

  const loadData = async () => {
    try {
      setLoading(true);
      const [incidentsRes, statsRes] = await Promise.all([
        incidentAPI.getAll(0, 100, filter === 'all' ? null : filter),
        incidentAPI.getStats()
      ]);
      
      const incidentsData = Array.isArray(incidentsRes) ? incidentsRes : incidentsRes?.incidents || [];
      setIncidents(incidentsData);
      setStats(statsRes || {});
    } catch (err) {
      console.error('Error loading incidents:', err);
    } finally {
      setLoading(false);
    }
  };

  const formatTime = (isoString) => {
    if (!isoString) return 'N/A';
    const date = new Date(isoString);
    return date.toLocaleString();
  };

  if (loading) {
    return <div className="text-center py-8">Loading incidents...</div>;
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-3xl font-bold">Incidents</h1>
          <p className="text-sm text-gray-500">
            Total: {stats.total || 0} | Pending: {stats.pending || 0} | Investigating: {stats.investigating || 0} | Resolved: {stats.resolved || 0}
          </p>
        </div>
        <div className="flex items-center space-x-4">
          <span className="text-sm text-gray-500">🔴 Live</span>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="mb-6 flex space-x-2 flex-wrap gap-2">
        {['all', 'pending', 'investigating', 'completed', 'resolved'].map((s) => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            className={`px-4 py-2 rounded-md capitalize ${
              filter === s ? 'bg-gray-800 text-white' : 'bg-gray-200 hover:bg-gray-300'
            }`}
          >
            {s}
          </button>
        ))}
      </div>

      {/* Incidents Table */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        {incidents.length === 0 ? (
          <div className="px-6 py-12 text-center text-gray-500">
            <div className="text-4xl mb-4">🔍</div>
            <p>No incidents found</p>
            <p className="text-sm">Wait for security events or create one manually</p>
          </div>
        ) : (
          <div className="divide-y divide-gray-200">
            {incidents.map((incident) => (
              <Link
                to={`/incidents/${incident.id}`}
                key={incident.id}
                className="block hover:bg-gray-50 transition"
              >
                <div className="px-6 py-4 flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3">
                      <span className="font-medium text-gray-900">
                        {incident.title}
                      </span>
                      {/* ✅ FIX: Use priority or severity */}
                      <SeverityBadge severity={incident.priority || incident.severity || 'MEDIUM'} />
                      <StatusBadge status={incident.status || 'pending'} />
                    </div>
                    <p className="text-sm text-gray-500 mt-1 line-clamp-1">
                      {incident.description ? incident.description.substring(0, 150) + '...' : 'No description'}
                    </p>
                    <div className="mt-1 flex items-center space-x-4 text-xs text-gray-400">
                      <span>🕐 {formatTime(incident.created_at)}</span>
                      {incident.source_type && <span>📁 {incident.source_type}</span>}
                    </div>
                  </div>
                  <div className="flex items-center space-x-4">
                    {incident.extra_data?.severity_score !== undefined && (
                      <span className="text-sm font-medium text-gray-600">
                        Score: {incident.extra_data.severity_score}/100
                      </span>
                    )}
                    <span className="text-gray-300">›</span>
                  </div>
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default IncidentList;