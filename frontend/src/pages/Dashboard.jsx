import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { incidentAPI } from '../services/api';
import StatusBadge from '../components/StatusBadge';
import SeverityBadge from '../components/SeverityBadge';

const Dashboard = () => {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({
    total: 0,
    pending: 0,
    investigating: 0,
    resolved: 0,
  });

  useEffect(() => {
    loadIncidents();
  }, []);

  const loadIncidents = async () => {
    try {
      const data = await incidentAPI.getAll();
      setIncidents(data);
      
      // Calculate stats
      const total = data.length;
      const pending = data.filter(i => i.status === 'pending').length;
      const investigating = data.filter(i => i.status === 'investigating').length;
      const resolved = data.filter(i => i.status === 'resolved' || i.status === 'completed').length;
      
      setStats({ total, pending, investigating, resolved });
      setLoading(false);
    } catch (error) {
      console.error('Failed to load incidents:', error);
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="text-center py-8">Loading incidents...</div>;
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <h1 className="text-3xl font-bold mb-8">Dashboard</h1>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <div className="bg-white p-6 rounded-lg shadow">
          <h3 className="text-gray-500 text-sm font-medium">Total Incidents</h3>
          <p className="text-3xl font-bold mt-2">{stats.total}</p>
        </div>
        <div className="bg-yellow-50 p-6 rounded-lg shadow border border-yellow-200">
          <h3 className="text-yellow-700 text-sm font-medium">Pending</h3>
          <p className="text-3xl font-bold mt-2">{stats.pending}</p>
        </div>
        <div className="bg-blue-50 p-6 rounded-lg shadow border border-blue-200">
          <h3 className="text-blue-700 text-sm font-medium">Investigating</h3>
          <p className="text-3xl font-bold mt-2">{stats.investigating}</p>
        </div>
        <div className="bg-green-50 p-6 rounded-lg shadow border border-green-200">
          <h3 className="text-green-700 text-sm font-medium">Resolved</h3>
          <p className="text-3xl font-bold mt-2">{stats.resolved}</p>
        </div>
      </div>

      {/* Recent Incidents */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200 flex justify-between items-center">
          <h2 className="text-xl font-semibold">Recent Incidents</h2>
          <Link to="/incidents/new" className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700">
            + New Incident
          </Link>
        </div>
        <div className="divide-y divide-gray-200">
          {incidents.slice(0, 5).map((incident) => (
            <Link to={`/incidents/${incident.id}`} key={incident.id} className="block hover:bg-gray-50">
              <div className="px-6 py-4 flex items-center justify-between">
                <div className="flex-1">
                  <h3 className="font-medium">{incident.title}</h3>
                  <p className="text-sm text-gray-500 truncate max-w-md">
                    {incident.description || 'No description'}
                  </p>
                </div>
                <div className="flex items-center space-x-4">
                  <SeverityBadge severity={incident.severity} />
                  <StatusBadge status={incident.status} />
                  <span className="text-sm text-gray-500">
                    {new Date(incident.created_at).toLocaleDateString()}
                  </span>
                </div>
              </div>
            </Link>
          ))}
          {incidents.length === 0 && (
            <div className="px-6 py-8 text-center text-gray-500">
              No incidents yet. Create your first incident!
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;