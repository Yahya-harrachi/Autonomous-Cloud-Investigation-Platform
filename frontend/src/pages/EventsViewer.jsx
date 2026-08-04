import React, { useState, useEffect, useRef } from 'react';
import { debugAPI } from '../services/api';
import SeverityBadge from '../components/SeverityBadge';

const EventsViewer = () => {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [totalEvents, setTotalEvents] = useState(0);
  const [filters, setFilters] = useState({
    count: 50,
    eventName: '',
    username: '',
    hoursBack: 24,
  });
  const [lastUpdated, setLastUpdated] = useState(null);
  const [healthStatus, setHealthStatus] = useState(null);

  const intervalRef = useRef(null);

  useEffect(() => {
    checkHealth();
    fetchEvents();
  }, []);

  useEffect(() => {
    if (autoRefresh) {
      intervalRef.current = setInterval(() => {
        fetchEvents();
      }, 30000);
    } else {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    }

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    };
  }, [autoRefresh, filters]);

  const checkHealth = async () => {
    try {
      const result = await debugAPI.checkCloudTrailHealth();
      setHealthStatus(result);
    } catch (err) {
      console.error('Health check failed:', err);
      setHealthStatus({ status: 'unhealthy', error: err.message });
    }
  };

  const fetchEvents = async () => {
    setLoading(true);
    setError(null);

    try {
      const result = await debugAPI.getCloudTrailEvents(
        filters.count,
        filters.eventName || null,
        filters.username || null,
        filters.hoursBack
      );

      // ✅ Use ALL events from the backend
      const eventsData = result.events || [];
      setEvents(eventsData);
      setTotalEvents(result.total_normalized || eventsData.length);
      setLastUpdated(new Date());

      console.log(`✅ Loaded ${eventsData.length} normalized events`);

      if (result.account_id) {
        setHealthStatus({
          status: 'healthy',
          account_id: result.account_id,
          region: result.region,
        });
      }
    } catch (err) {
      console.error('Error fetching events:', err);
      setError(err.response?.data?.detail || 'Failed to fetch CloudTrail events.');
      setEvents([]);
    } finally {
      setLoading(false);
    }
  };

  const handleFilterChange = (key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }));
  };

  const applyFilters = () => {
    fetchEvents();
  };

  const formatTime = (isoString) => {
    if (!isoString) return 'N/A';
    try {
      const date = new Date(isoString);
      return date.toLocaleString();
    } catch {
      return isoString;
    }
  };

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-3xl font-bold">CloudTrail Events</h1>
          <p className="text-sm text-gray-500">
            Normalized events from AWS CloudTrail with severity scoring
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <span className={`text-sm px-3 py-1 rounded-full ${
            healthStatus?.status === 'healthy' 
              ? 'bg-green-100 text-green-700' 
              : 'bg-red-100 text-red-700'
          }`}>
            {healthStatus?.status === 'healthy' ? '🟢 Connected' : '🔴 Disconnected'}
          </span>
          {healthStatus?.account_id && (
            <span className="text-xs text-gray-500">
              Account: {healthStatus.account_id}
            </span>
          )}
        </div>
      </div>

      {/* Controls */}
      <div className="bg-white rounded-lg shadow p-4 mb-6">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center space-x-2">
            <label className="text-sm font-medium text-gray-700">Count:</label>
            <select
              value={filters.count}
              onChange={(e) => handleFilterChange('count', parseInt(e.target.value))}
              className="px-3 py-1 border border-gray-300 rounded-md text-sm"
            >
              <option value="10">10</option>
              <option value="25">25</option>
              <option value="50">50</option>
              <option value="100">100</option>
            </select>
          </div>

          <div className="flex items-center space-x-2">
            <label className="text-sm font-medium text-gray-700">Hours Back:</label>
            <select
              value={filters.hoursBack}
              onChange={(e) => handleFilterChange('hoursBack', parseInt(e.target.value))}
              className="px-3 py-1 border border-gray-300 rounded-md text-sm"
            >
              <option value="1">1 hour</option>
              <option value="6">6 hours</option>
              <option value="12">12 hours</option>
              <option value="24">24 hours</option>
              <option value="48">48 hours</option>
              <option value="168">7 days</option>
            </select>
          </div>

          <div className="flex items-center space-x-2">
            <label className="text-sm font-medium text-gray-700">Event Name:</label>
            <input
              type="text"
              value={filters.eventName}
              onChange={(e) => handleFilterChange('eventName', e.target.value)}
              placeholder="e.g. ConsoleLogin"
              className="px-3 py-1 border border-gray-300 rounded-md text-sm w-40"
            />
          </div>

          <div className="flex items-center space-x-2">
            <label className="text-sm font-medium text-gray-700">Username:</label>
            <input
              type="text"
              value={filters.username}
              onChange={(e) => handleFilterChange('username', e.target.value)}
              placeholder="e.g. admin"
              className="px-3 py-1 border border-gray-300 rounded-md text-sm w-32"
            />
          </div>

          <button
            onClick={applyFilters}
            disabled={loading}
            className="px-4 py-1 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 text-sm"
          >
            {loading ? 'Loading...' : 'Apply Filters'}
          </button>

          <button
            onClick={fetchEvents}
            disabled={loading}
            className="px-4 py-1 bg-gray-600 text-white rounded-md hover:bg-gray-700 disabled:opacity-50 text-sm"
          >
            🔄 Refresh
          </button>

          <div className="flex items-center space-x-2 ml-auto">
            <label className="text-sm font-medium text-gray-700">Auto-Refresh:</label>
            <button
              onClick={() => setAutoRefresh(!autoRefresh)}
              className={`px-3 py-1 rounded-md text-sm ${
                autoRefresh 
                  ? 'bg-green-600 text-white hover:bg-green-700' 
                  : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              }`}
            >
              {autoRefresh ? 'ON (30s)' : 'OFF'}
            </button>
          </div>
        </div>

        <div className="mt-3 flex justify-between text-sm text-gray-500 border-t pt-2">
          <span>Total: {totalEvents} normalized events</span>
          <span>
            Filters: {filters.eventName ? `Event: ${filters.eventName}` : 'All events'}
            {filters.username && ` | User: ${filters.username}`}
            {filters.hoursBack && ` | Last ${filters.hoursBack} hours`}
          </span>
          <span>
            Last updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : 'Never'}
          </span>
        </div>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg mb-6">
          <strong>Error:</strong> {error}
        </div>
      )}

      {loading ? (
        <div className="text-center py-12">
          <div className="text-gray-500">Loading normalized events...</div>
        </div>
      ) : events.length === 0 ? (
        <div className="bg-white rounded-lg shadow p-12 text-center text-gray-500">
          <div className="text-4xl mb-4">📭</div>
          <p>No normalized events found</p>
          <p className="text-sm mt-2">
            {error ? 'Check your AWS configuration' : 'Try adjusting filters'}
          </p>
        </div>
      ) : (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <div className="divide-y divide-gray-200">
            {events.map((event, index) => (
              <div key={event.event_id || index} className="px-6 py-4 hover:bg-gray-50">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3">
                      <span className="font-medium text-gray-900">
                        {event.event_name || 'Unknown Event'}
                      </span>
                      <SeverityBadge severity={event.severity || 'INFO'} />
                      <span className="text-xs text-gray-500 bg-gray-100 px-2 py-1 rounded">
                        {event.provider_type || 'N/A'}
                      </span>
                    </div>

                    <div className="mt-1 flex items-center space-x-4 text-sm text-gray-500">
                      <span>👤 {event.actor || 'N/A'}</span>
                      {/* ✅ Always show IP with fallback */}
                      <span>🌐 {event.actor_ip || 'N/A'}</span>
                      {/* ✅ Always show region with fallback */}
                      <span>🌍 {event.region || 'N/A'}</span>
                      <span>🕐 {formatTime(event.timestamp)}</span>
                    </div>

                    {event.severity_score !== undefined && (
                      <div className="mt-1 text-sm">
                        <span className="font-medium">
                          Score: {event.severity_score}/100
                        </span>
                        {event.severity_reason && (
                          <span className="text-xs text-gray-400 ml-2">
                            {event.severity_reason.substring(0, 100)}...
                          </span>
                        )}
                      </div>
                    )}

                    {event.resource && event.resource !== 'unknown' && (
                      <div className="mt-1 text-xs text-gray-400">
                        Resource: {event.resource}
                      </div>
                    )}
                  </div>

                  <button
                    onClick={() => {
                      console.log('Event details:', event);
                      alert(JSON.stringify(event, null, 2));
                    }}
                    className="text-blue-600 hover:text-blue-800 text-sm ml-4"
                  >
                    View JSON
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="mt-4 text-xs text-gray-400 text-center">
        Normalized events from AWS CloudTrail with severity scoring from the Risk Engine.
      </div>
    </div>
  );
};

export default EventsViewer;