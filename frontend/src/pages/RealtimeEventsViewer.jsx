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
  
  // ✅ Track processed events by their unique identifiers
  const processedEventIds = useRef(new Set());
  const processedIncidentIds = useRef(new Set());

  // ✅ Generate UNIQUE event ID that identifies the EXACT event
  const getEventId = (event) => {
    // Priority 1: Use CloudTrail's unique eventID (best option)
    if (event.event_id) return `event_${event.event_id}`;
    if (event.id) return `event_${event.id}`;
    
    // Priority 2: Use eventName + timestamp + source IP + region + event version
    // This ensures different events at different times are NOT skipped
    const timestamp = event.timestamp || event.eventTime || event.time || '';
    const eventName = event.event_name || event.eventName || 'unknown';
    const sourceIp = event.actor_ip || event.sourceIP || 'unknown';
    const region = event.region || event.awsRegion || 'unknown';
    const eventVersion = event.eventVersion || event.version || '1.0';
    
    // Include event-specific details to avoid false duplicates
    const eventSpecific = event.eventType || event.type || '';
    const eventSource = event.provider || event.eventSource || '';
    
    // Create a unique fingerprint for this specific event
    return `event_${eventName}_${timestamp}_${sourceIp}_${region}_${eventVersion}_${eventSpecific}_${eventSource}`.replace(/[^a-zA-Z0-9]/g, '_');
  };

  // ✅ Generate UNIQUE incident ID
  const getIncidentId = (incident) => {
    if (incident.id) return `incident_${incident.id}`;
    if (incident.incident_id) return `incident_${incident.incident_id}`;
    
    // Include timestamp and title to differentiate similar incidents
    const timestamp = incident.created_at || incident.timestamp || incident.time || '';
    const title = incident.title || 'unknown';
    const priority = incident.priority || incident.severity || 'unknown';
    
    return `incident_${title}_${timestamp}_${priority}`.replace(/[^a-zA-Z0-9]/g, '_');
  };

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
      // ✅ Generate unique ID for this EXACT event
      const eventId = getEventId(event);
      
      // Log for debugging
      console.log(`📥 Received event: ${event.event_name || 'Unknown'}`, {
        id: eventId,
        timestamp: event.timestamp || event.eventTime,
        event_id: event.event_id || event.id
      });
      
      // ✅ ONLY skip if this EXACT event was already processed
      if (processedEventIds.current.has(eventId)) {
        console.log(`🔄 Skipping EXACT duplicate event: ${event.event_name}`, eventId);
        return;
      }
      
      // Add to processed set
      processedEventIds.current.add(eventId);
      
      // Clean up after 1 minute (events shouldn't be duplicates after 1 minute)
      setTimeout(() => {
        processedEventIds.current.delete(eventId);
        console.log(`🧹 Cleaned up event ID from cache: ${eventId}`);
      }, 60000); // 1 minute
      
      setEvents(prev => {
        // ✅ Double-check: only skip if EXACT duplicate exists in state
        const exists = prev.some(e => getEventId(e) === eventId);
        if (exists) {
          console.log(`🔄 Event already in state, skipping: ${eventId}`);
          return prev;
        }
        
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
      // ✅ Generate unique ID for this EXACT incident
      const incidentId = getIncidentId(incident);
      
      console.log(`📥 Received incident: ${incident.title || 'Unknown'}`, {
        id: incidentId,
        timestamp: incident.created_at || incident.timestamp,
        incident_id: incident.id || incident.incident_id
      });
      
      // ✅ ONLY skip if this EXACT incident was already processed
      if (processedIncidentIds.current.has(incidentId)) {
        console.log(`🔄 Skipping EXACT duplicate incident: ${incident.title}`, incidentId);
        return;
      }
      
      // Add to processed set
      processedIncidentIds.current.add(incidentId);
      
      // Clean up after 1 minute
      setTimeout(() => {
        processedIncidentIds.current.delete(incidentId);
      }, 60000);
      
      setIncidents(prev => {
        // ✅ Double-check: only skip if EXACT duplicate exists in state
        const exists = prev.some(i => getIncidentId(i) === incidentId);
        if (exists) {
          console.log(`🔄 Incident already in state, skipping: ${incidentId}`);
          return prev;
        }
        
        return [incident, ...prev];
      });
      
      setStats(prev => ({
        ...prev,
        total_incidents: prev.total_incidents + 1,
      }));
      
      // Show notification
      if (Notification.permission === 'granted') {
        new Notification(`🚨 ${incident.severity || incident.priority}: ${incident.title}`);
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
      
      // Clear caches on unmount
      processedEventIds.current.clear();
      processedIncidentIds.current.clear();
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
              <span key={getIncidentId(incident) || i} className="text-sm bg-red-100 text-red-800 px-2 py-1 rounded">
                {incident.severity || incident.priority}: {incident.title}
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
            events.map((event) => {
              // ✅ Use proper unique key for React rendering
              const key = getEventId(event) || `event_${Math.random().toString()}`;
              return (
                <div key={key} className="px-6 py-3 hover:bg-gray-50">
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
                        <span className="text-xs text-green-600 bg-green-50 px-2 py-1 rounded animate-pulse">
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
              );
            })
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