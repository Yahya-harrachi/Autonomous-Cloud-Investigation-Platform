import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { incidentAPI } from '../services/api';
import StatusBadge from '../components/StatusBadge';
import SeverityBadge from '../components/SeverityBadge';
import websocketService from '../services/websocket';

const Dashboard = () => {
  const [incidents, setIncidents] = useState([]);
  const [stats, setStats] = useState({
    total: 0,
    pending: 0,
    investigating: 0,
    resolved: 0
  });
  const [loading, setLoading] = useState(true);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    loadData();

    const onConnected = () => setIsConnected(true);
    const onDisconnected = () => setIsConnected(false);

    websocketService.on('connected', onConnected);
    websocketService.on('disconnected', onDisconnected);

    if (!websocketService.isConnected) {
      websocketService.connect();
    }

    return () => {
      websocketService.off('connected', onConnected);
      websocketService.off('disconnected', onDisconnected);
    };
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [incidentsRes, statsRes] = await Promise.all([
        incidentAPI.getAll(0, 10),
        incidentAPI.getStats()
      ]);

      const incidentsData = Array.isArray(incidentsRes) ? incidentsRes : incidentsRes?.incidents || [];
      setIncidents(incidentsData);
      setStats(statsRes || { total: 0, pending: 0, investigating: 0, resolved: 0 });
      setIsConnected(websocketService.isConnected);
    } catch (err) {
      console.error('Error loading data:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="text-center py-8">Loading...</div>;
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="flex justify-between items-center mb-8">
        <h1 className="text-3xl font-bold">Dashboard</h1>
        <div className="flex items-center space-x-2">
          <div className={`w-3 h-3 rounded-full ${isConnected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
          <span className="text-sm font-medium">
            {isConnected ? '🟢 Live' : '🔴 Disconnected'}
          </span>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <div className="bg-white p-6 rounded-lg shadow border border-gray-200">
          <h3 className="text-gray-500 text-sm font-medium">Total Incidents</h3>
          <p className="text-3xl font-bold mt-2">{stats.total || 0}</p>
        </div>
        <div className="bg-yellow-50 p-6 rounded-lg shadow border border-yellow-200">
          <h3 className="text-yellow-700 text-sm font-medium">Pending</h3>
          <p className="text-3xl font-bold mt-2">{stats.pending || 0}</p>
        </div>
        <div className="bg-blue-50 p-6 rounded-lg shadow border border-blue-200">
          <h3 className="text-blue-700 text-sm font-medium">Investigating</h3>
          <p className="text-3xl font-bold mt-2">{stats.investigating || 0}</p>
        </div>
        <div className="bg-green-50 p-6 rounded-lg shadow border border-green-200">
          <h3 className="text-green-700 text-sm font-medium">Resolved</h3>
          <p className="text-3xl font-bold mt-2">{stats.resolved || 0}</p>
        </div>
      </div>

      {/* Recent Incidents */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200 flex justify-between items-center">
          <h2 className="text-xl font-semibold">Recent Incidents</h2>
          <Link to="/incidents" className="text-blue-600 hover:text-blue-800">
            View All →
          </Link>
        </div>
        <div className="divide-y divide-gray-200">
          {incidents.length === 0 ? (
            <div className="px-6 py-8 text-center text-gray-500">No incidents found</div>
          ) : (
            incidents.map((incident) => (
              <Link to={`/incidents/${incident.id}`} key={incident.id} className="block hover:bg-gray-50">
                <div className="px-6 py-4 flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3">
                      <h3 className="font-medium">{incident.title}</h3>
                      <SeverityBadge severity={incident.priority || incident.severity || 'MEDIUM'} />
                      <StatusBadge status={incident.status || 'pending'} />
                    </div>
                    <p className="text-sm text-gray-500 truncate max-w-md">
                      {incident.description ? incident.description.substring(0, 100) + '...' : 'No description'}
                    </p>
                  </div>
                  <span className="text-sm text-gray-500">
                    {new Date(incident.created_at).toLocaleDateString()}
                  </span>
                </div>
              </Link>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;