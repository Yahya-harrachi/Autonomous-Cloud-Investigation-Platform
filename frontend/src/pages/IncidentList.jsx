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
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    loadData();

    const onConnected = () => setIsConnected(true);
    const onDisconnected = () => setIsConnected(false);
    const onNewIncident = (incident) => {
      console.log('🚨 New incident received:', incident);
      
      // ✅ Only add if it matches current filter
      const shouldAdd = filter === 'all' || filter === incident.status;
      if (shouldAdd) {
        setIncidents(prev => [incident, ...prev]);
      }
      
      // ✅ Update stats
      setStats(prev => ({
        ...prev,
        total: (prev.total || 0) + 1,
        pending: incident.status === 'pending' ? (prev.pending || 0) + 1 : (prev.pending || 0),
        investigating: incident.status === 'investigating' ? (prev.investigating || 0) + 1 : (prev.investigating || 0),
        resolved: incident.status === 'resolved' ? (prev.resolved || 0) + 1 : (prev.resolved || 0),
      }));
    };

    websocketService.on('connected', onConnected);
    websocketService.on('disconnected', onDisconnected);
    websocketService.on('new_incident', onNewIncident);

    if (!websocketService.isConnected) {
      websocketService.connect();
    }

    return () => {
      websocketService.off('connected', onConnected);
      websocketService.off('disconnected', onDisconnected);
      websocketService.off('new_incident', onNewIncident);
    };
  }, [filter]);

  const loadData = async () => {
    try {
      setLoading(true);
      
      // ✅ Pass filter to API
      const filterStatus = filter === 'all' ? null : filter;
      const [incidentsRes, statsRes] = await Promise.all([
        incidentAPI.getAll(0, 100, filterStatus),
        incidentAPI.getStats()
      ]);

      const incidentsData = Array.isArray(incidentsRes) ? incidentsRes : incidentsRes?.incidents || [];
      setIncidents(incidentsData);
      setStats(statsRes || {});
      setIsConnected(websocketService.isConnected);
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

  const getSeverity = (incident) => {
    return incident.priority || incident.severity || 'MEDIUM';
  };

  const getScore = (incident) => {
    return incident.extra_data?.severity_score || null;
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="text-gray-500">Loading incidents...</div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-3xl font-bold">Incidents</h1>
          <p className="text-sm text-gray-500">
            Total: {stats.total || 0} | Pending: {stats.pending || 0} | Investigating: {stats.investigating || 0} | Resolved: {stats.resolved || 0}
          </p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <div className={`w-3 h-3 rounded-full ${isConnected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
            <span className="text-sm font-medium">
              {isConnected ? '🟢 Live' : '🔴 Disconnected'}
            </span>
          </div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="mb-6 flex space-x-2 flex-wrap gap-2">
        {['all', 'pending', 'investigating', 'completed', 'resolved'].map((s) => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            className={`px-4 py-2 rounded-md capitalize ${
              filter === s 
                ? 'bg-gray-800 text-white' 
                : 'bg-gray-200 hover:bg-gray-300'
            }`}
          >
            {s === 'all' ? 'All' : s}
          </button>
        ))}
      </div>

      {/* Incidents List */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        {incidents.length === 0 ? (
          <div className="px-6 py-12 text-center text-gray-500">
            <div className="text-4xl mb-4">🔍</div>
            <p>No incidents found</p>
            <p className="text-sm">
              {filter === 'all' 
                ? 'Wait for security events or create one manually' 
                : `No ${filter} incidents found`}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-gray-200">
            {incidents.map((incident) => {
              const severity = getSeverity(incident);
              const status = incident.status || 'pending';
              const score = getScore(incident);
              
              return (
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
                        <SeverityBadge severity={severity} />
                        <StatusBadge status={status} />
                      </div>
                      <p className="text-sm text-gray-500 mt-1 line-clamp-1 max-w-2xl">
                        {incident.description 
                          ? incident.description.substring(0, 150) + '...' 
                          : 'No description'}
                      </p>
                      <div className="mt-1 flex items-center space-x-4 text-xs text-gray-400">
                        <span>🕐 {formatTime(incident.created_at)}</span>
                        {incident.source_type && (
                          <span>📁 {incident.source_type}</span>
                        )}
                        {incident.extra_data?.event_name && (
                          <span>📋 {incident.extra_data.event_name}</span>
                        )}
                        {incident.extra_data?.actor && (
                          <span>👤 {incident.extra_data.actor}</span>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center space-x-4">
                      {score !== null && (
                        <span className="text-sm font-medium text-gray-600">
                          Score: {score}/100
                        </span>
                      )}
                      <span className="text-gray-300">›</span>
                    </div>
                  </div>
                </Link>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};

export default IncidentList;