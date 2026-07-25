import React, { useState, useEffect, useRef } from 'react';
import { debugAPI } from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';

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

  // Check CloudTrail health on mount
  useEffect(() => {
    checkHealth();
  }, []);

  // Auto-refresh effect
  useEffect(() => {
    if (autoRefresh) {
      intervalRef.current = setInterval(() => {
        fetchEvents();
      }, 30000); // Refresh every 30 seconds
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
      
      setEvents(result.events || []);
      setTotalEvents(result.total_events || 0);
      setLastUpdated(new Date());
      
      // Update health status if available
      if (result.account_id) {
        setHealthStatus({
          status: 'healthy',
          account_id: result.account_id,
          region: result.region,
        });
      }
    } catch (err) {
      console.error('Error fetching events:', err);
      setError(err.response?.data?.detail || 'Failed to fetch CloudTrail events. Make sure AWS is configured correctly.');
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

  const getSeverityFromEvent = (event) => {
    // Try to determine severity from event
    const eventName = event.event_name || '';
    const severityMap = {
      'ConsoleLogin': 'MEDIUM',
      'RunInstances': 'HIGH',
      'TerminateInstances': 'HIGH',
      'CreateBucket': 'LOW',
      'DeleteBucket': 'MEDIUM',
      'PutBucketPolicy': 'HIGH',
      'CreateKeyPair': 'MEDIUM',
      'DeleteKeyPair': 'LOW',
      'AuthorizeSecurityGroupIngress': 'CRITICAL',
      'RevokeSecurityGroupIngress': 'MEDIUM',
      'CreateUser': 'HIGH',
      'DeleteUser': 'MEDIUM',
      'AttachUserPolicy': 'CRITICAL',
      'DetachUserPolicy': 'HIGH',
    };
    
    return severityMap[eventName] || 'LOW';
  };

  const formatTime = (isoString) => {
    if (!isoString) return 'N/A';
    const date = new Date(isoString);
    return date.toLocaleString();
  };

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-3xl font-bold">CloudTrail Events</h1>
          <p className="text-sm text-gray-500">
            Real-time events from AWS CloudTrail
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

        {/* Status bar */}
        <div className="mt-3 flex justify-between text-sm text-gray-500 border-t pt-2">
          <span>Total: {totalEvents} events</span>
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

      {/* Error message */}
      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg mb-6">
          <strong>Error:</strong> {error}
        </div>
      )}

      {/* Events List */}
      {loading ? (
        <div className="text-center py-12">
          <div className="text-gray-500">Loading CloudTrail events...</div>
        </div>
      ) : events.length === 0 ? (
        <div className="bg-white rounded-lg shadow p-12 text-center text-gray-500">
          <div className="text-4xl mb-4">📭</div>
          <p>No CloudTrail events found</p>
          <p className="text-sm mt-2">
            {error ? 'Check your AWS configuration' : 'Try adjusting filters or generating some activity'}
          </p>
          {!error && (
            <button
              onClick={() => {
                // Generate some activity
                window.open('https://console.aws.amazon.com/s3/home', '_blank');
              }}
              className="mt-4 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 text-sm"
            >
              Generate Activity in AWS
            </button>
          )}
        </div>
      ) : (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <div className="divide-y divide-gray-200">
            {events.map((event, index) => {
              const severity = getSeverityFromEvent(event);
              const summary = event.summary || {};
              
              return (
                <div key={event.event_id || index} className="px-6 py-4 hover:bg-gray-50">
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3">
                        <span className="font-medium text-gray-900">
                          {event.event_name || 'Unknown Event'}
                        </span>
                        <SeverityBadge severity={severity} />
                        <span className="text-xs text-gray-500 bg-gray-100 px-2 py-1 rounded">
                          {event.event_source || 'N/A'}
                        </span>
                      </div>
                      <div className="mt-1 flex items-center space-x-4 text-sm text-gray-500">
                        <span>👤 {event.username || 'N/A'}</span>
                        {summary.source_ip && (
                          <span>🌐 {summary.source_ip}</span>
                        )}
                        {event.region && (
                          <span>🌍 {event.region}</span>
                        )}
                        <span>🕐 {formatTime(event.event_time)}</span>
                      </div>
                      {/* Resources */}
                      {event.resources && event.resources.length > 0 && (
                        <div className="mt-1 text-xs text-gray-400">
                          Resources: {event.resources.map(r => r.ResourceName || r.ARN).filter(Boolean).join(', ')}
                        </div>
                      )}
                    </div>
                    <button
                      onClick={() => {
                        // View event details - expand/show JSON
                        console.log('Event details:', event);
                        alert(JSON.stringify(event.cloudtrail_event, null, 2));
                      }}
                      className="text-blue-600 hover:text-blue-800 text-sm"
                    >
                      View JSON
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Footer */}
      <div className="mt-4 text-xs text-gray-400 text-center">
        Events retrieved from AWS CloudTrail. Only {events.length} events shown.
        Use filters to narrow down results.
      </div>
    </div>
  );
};

export default EventsViewer;