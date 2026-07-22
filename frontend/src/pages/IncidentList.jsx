import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { incidentAPI } from '../services/api';
import StatusBadge from '../components/StatusBadge';
import SeverityBadge from '../components/SeverityBadge';

const IncidentList = () => {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const [stats, setStats] = useState({});

  useEffect(() => {
    loadData();
  }, [filter]);

  const loadData = async () => {
    try {
      setLoading(true);
      const [incidentsRes, statsRes] = await Promise.all([
        incidentAPI.getAll(0, 100, filter === 'all' ? null : filter),
        incidentAPI.getStats()
      ]);
      setIncidents(incidentsRes.incidents || []);
      setStats(statsRes || {});
    } catch (err) {
      console.error('Error loading incidents:', err);
    } finally {
      setLoading(false);
    }
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
        <button
          onClick={async () => {
            try {
              await incidentAPI.runIngestion(3);
              loadData();
            } catch (err) {
              console.error('Error running ingestion:', err);
            }
          }}
          className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700"
        >
          Generate Events
        </button>
      </div>

      {/* Filter Bar */}
      <div className="mb-6 flex space-x-2">
        {['all', 'pending', 'investigating', 'completed', 'resolved'].map((s) => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            className={`px-4 py-2 rounded-md ${
              filter === s ? 'bg-gray-800 text-white' : 'bg-gray-200 hover:bg-gray-300'
            }`}
          >
            {s.charAt(0).toUpperCase() + s.slice(1)}
          </button>
        ))}
      </div>

      {/* Incidents Table */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Title
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Priority
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Source
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Created
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {incidents.length === 0 ? (
              <tr>
                <td colSpan="5" className="px-6 py-8 text-center text-gray-500">
                  No incidents found
                </td>
              </tr>
            ) : (
              incidents.map((incident) => (
                <tr key={incident.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4">
                    <Link to={`/incidents/${incident.id}`} className="text-blue-600 hover:underline">
                      {incident.title}
                    </Link>
                  </td>
                  <td className="px-6 py-4">
                    <SeverityBadge severity={(incident.priority || incident.severity || 'MEDIUM').toUpperCase()} />
                  </td>
                  <td className="px-6 py-4">
                    <StatusBadge status={incident.status || 'pending'} />
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-500">
                    {incident.source_type || 'N/A'}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-500">
                    {new Date(incident.created_at).toLocaleDateString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default IncidentList;