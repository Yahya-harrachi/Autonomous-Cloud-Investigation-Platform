import React, { useState, useEffect, useRef } from 'react';
import SeverityBadge from '../components/SeverityBadge';
import websocketService from '../services/websocket';

const RealtimeEventsViewer = () => {
  const [events, setEvents] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [incidents, setIncidents] = useState([]);
  const [stats, setStats] = useState({
    total_events: 0,
    total_incidents: 0,
  });
  const eventsEndRef = useRef(null);

  // Connect to WebSocket on mount
  useEffect(() => {
    // Listen for WebSocket events
    const onConnected = () => {
      setIsConnected(true);
      console.log('✅ Connected to real-time events');
    };

    const onDisconnected = () => {
      setIsConnected(false);
    };

    const onNewEvent = (event) => {
      setEvents(prev => {
        const newEvents = [event, ...prev];
        // Keep only last 100 events
        return newEvents.slice(0, 100);
      });
      
      setStats(prev => ({
        ...prev,
        total_events: prev.total_events + 1,
      }));
      
      // Auto-scroll to top
      if (eventsEndRef.current) {
        eventsEndRef.current.scrollIntoView({ behavior: 'smooth' });
      }
    };

    const onNewIncident = (incident) => {
      setIncidents(prev => [incident, ...prev]);
      setStats(prev => ({
        ...prev,
        total_incidents: prev.total_incidents + 1,
      }));
      
      // Show notification
      if (Notification.permission === 'granted') {
        new Notification(`🚨 ${incident.severity}: ${incident.title}`);
      }
    };

    // Register listeners
    websocketService.on('connected', onConnected);
    websocketService.on('disconnected', onDisconnected);
    websocketService.on('new_event', onNewEvent);
    websocketService.on('new_incident', onNewIncident);

    // Connect to WebSocket
    websocketService.connect();

    // Request notification permission
    if (Notification.permission === 'default') {
      Notification.requestPermission();
    }

    // Cleanup on unmount
    return () => {
      websocketService.off('connected', onConnected);
      websocketService.off('disconnected', onDisconnected);
      websocketService.off('new_event', onNewEvent);
      websocketService.off('new_incident', onNewIncident);
      websocketService.disconnect();
    };
  }, []);

  const formatTime = (isoString) => {
    if (!isoString) return 'N/A';
    try {
      const date = new Date(isoString);
      return date.toLocaleTimeString();
    } catch {
      return isoString;
    }
  };

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-3xl font-bold">📡 Real-time Events</h1>
          <p className="text-sm text-gray-500">
            Live events from AWS CloudTrail
          </p>
        </div>
        <div className="flex items-center space-x-4">
          {/* Connection Status */}
          <div className="flex items-center space-x-2">
            <div className={`w-3 h-3 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`} />
            <span className="text-sm font-medium">
              {isConnected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
          {/* Stats */}
          <div className="text-sm text-gray-500">
            Events: {stats.total_events} | Incidents: {stats.total_incidents}
          </div>
        </div>
      </div>

      {/* Incidents Alert Bar */}
      {incidents.length > 0 && (
        <div className="mb-4 bg-red-50 border border-red-200 rounded-lg p-3">
          <div className="flex items-center space-x-2">
            <span className="text-red-600 font-bold">🚨 New Incidents:</span>
            {incidents.slice(0, 3).map((incident, i) => (
              <span key={i} className="text-sm bg-red-100 text-red-800 px-2 py-1 rounded">
                {incident.severity}: {incident.title}
              </span>
            ))}
            {incidents.length > 3 && (
              <span className="text-sm text-gray-500">+{incidents.length - 3} more</span>
            )}
          </div>
        </div>
      )}

      {/* Events List */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <div className="divide-y divide-gray-200 max-h-96 overflow-y-auto">
          {events.length === 0 ? (
            <div className="px-6 py-12 text-center text-gray-500">
              {isConnected ? (
                <>
                  <div className="text-4xl mb-4">📡</div>
                  <p>Waiting for events...</p>
                  <p className="text-sm">Events will appear here in real-time</p>
                </>
              ) : (
                <>
                  <div className="text-4xl mb-4">🔌</div>
                  <p>Connecting to real-time events...</p>
                  <p className="text-sm">Please wait for WebSocket connection</p>
                </>
              )}
            </div>
          ) : (
            events.map((event, index) => (
              <div key={event.event_id || index} className="px-6 py-3 hover:bg-gray-50">
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
                      <span className="text-xs text-green-600 bg-green-50 px-2 py-1 rounded">
                        LIVE
                      </span>
                    </div>
                    <div className="mt-1 flex items-center space-x-4 text-sm text-gray-500">
                      <span>👤 {event.actor || 'N/A'}</span>
                      {event.actor_ip && <span>🌐 {event.actor_ip}</span>}
                      {event.region && <span>🌍 {event.region}</span>}
                      <span>🕐 {formatTime(event.timestamp)}</span>
                    </div>
                    {event.severity_score !== undefined && (
                      <div className="mt-1 text-xs text-gray-400">
                        Score: {event.severity_score}/100
                      </div>
                    )}
                  </div>
                  <button
                    onClick={() => {
                      console.log('Event details:', event);
                      alert(JSON.stringify(event, null, 2));
                    }}
                    className="text-blue-600 hover:text-blue-800 text-sm"
                  >
                    View JSON
                  </button>
                </div>
              </div>
            ))
          )}
          <div ref={eventsEndRef} />
        </div>
      </div>

      {/* Footer */}
      <div className="mt-4 text-xs text-gray-400 text-center">
        {isConnected ? (
          <span>🟢 Live connection active. New events appear automatically.</span>
        ) : (
          <span>🔴 Disconnected. Attempting to reconnect...</span>
        )}
      </div>
    </div>
  );
};

export default RealtimeEventsViewer;