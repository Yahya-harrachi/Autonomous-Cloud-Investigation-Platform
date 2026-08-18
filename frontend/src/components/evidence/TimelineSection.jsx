// frontend/src/components/evidence/TimelineSection.jsx
import React, { useState, useEffect } from 'react';
import api from '../../services/api';

const TimelineSection = ({ incidentId }) => {
  const [timeline, setTimeline] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expandedEvents, setExpandedEvents] = useState(new Set());
  const [showAll, setShowAll] = useState(false);

  useEffect(() => {
    loadTimeline();
  }, [incidentId]);

  const loadTimeline = async () => {
    setLoading(true);
    try {
      const response = await api.get(`/incidents/${incidentId}/evidence`);
      const artifacts = response.data || [];
      
      const cloudtrailArtifact = artifacts.find(a => a.artifact_type === 'CloudTrailEvent');
      
      if (cloudtrailArtifact && cloudtrailArtifact.content?.timeline) {
        // ✅ Get all timeline events
        const allEvents = cloudtrailArtifact.content.timeline;
        setTimeline(allEvents);
      } else {
        setTimeline([]);
      }
    } catch (err) {
      setError(err.message);
      console.error('Error loading timeline:', err);
    } finally {
      setLoading(false);
    }
  };

  const toggleEvent = (index) => {
    const newExpanded = new Set(expandedEvents);
    if (newExpanded.has(index)) {
      newExpanded.delete(index);
    } else {
      newExpanded.add(index);
    }
    setExpandedEvents(newExpanded);
  };

  const getEventIcon = (event) => {
    if (event.is_trigger) return '🚨';
    if (event.priority === 'high') return '🔴';
    if (event.priority === 'recon') return '🔍';
    return '•';
  };

  const getEventColor = (event) => {
    if (event.is_trigger) return 'bg-red-50 border-red-200';
    if (event.priority === 'high') return 'bg-orange-50 border-orange-200';
    if (event.priority === 'recon') return 'bg-blue-50 border-blue-200';
    return 'bg-gray-50 border-gray-200';
  };

  // ✅ Get display events - show all or first 15
  const displayEvents = showAll ? timeline : timeline.slice(0, 15);

  if (loading) {
    return (
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center justify-center py-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
          <span className="ml-3 text-gray-600">Loading timeline...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="text-center py-4 text-red-600">
          ❌ Error loading timeline: {error}
        </div>
      </div>
    );
  }

  if (timeline.length === 0) {
    return (
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="text-center py-8 text-gray-500">
          <div className="text-4xl mb-2">🕐</div>
          <p>No timeline events available for this incident</p>
          <p className="text-sm text-gray-400 mt-1">
            Timeline is generated from CloudTrail evidence
          </p>
        </div>
      </div>
    );
  }

  // Group events by date
  const groupedEvents = displayEvents.reduce((acc, event, index) => {
    const time = event.event_time ? new Date(event.event_time).toLocaleDateString() : 'Unknown';
    if (!acc[time]) acc[time] = [];
    acc[time].push({ ...event, index });
    return acc;
  }, {});

  const hasMoreEvents = timeline.length > 15;

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-lg font-bold">🕐 Investigation Timeline</h2>
          <p className="text-sm text-gray-500">
            {timeline.length} events found
            {!showAll && timeline.length > 15 && ` (showing last 15)`}
          </p>
        </div>
        {hasMoreEvents && (
          <button
            onClick={() => setShowAll(!showAll)}
            className="px-3 py-1 text-sm bg-blue-50 text-blue-600 rounded hover:bg-blue-100"
          >
            {showAll ? 'Show Less' : `Show All (${timeline.length})`}
          </button>
        )}
      </div>

      <div className="relative">
        {/* Timeline Line */}
        <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-gray-200"></div>

        {/* Events */}
        <div className="space-y-4">
          {Object.entries(groupedEvents).map(([date, events]) => (
            <div key={date}>
              {/* Date Header */}
              <div className="flex items-center space-x-2 mb-2">
                <span className="text-xs font-medium text-gray-500 bg-gray-100 px-2 py-1 rounded">
                  {date}
                </span>
              </div>

              {events.map((event) => (
                <div
                  key={event.index}
                  className={`relative pl-10 ml-2 p-3 rounded-lg border ${getEventColor(event)} hover:shadow-sm transition-shadow cursor-pointer`}
                  onClick={() => toggleEvent(event.index)}
                >
                  {/* Timeline Dot */}
                  <div className={`absolute left-2 top-3 w-3 h-3 rounded-full border-2 ${
                    event.is_trigger ? 'bg-red-500 border-red-600' :
                    event.priority === 'high' ? 'bg-orange-500 border-orange-600' :
                    event.priority === 'recon' ? 'bg-blue-500 border-blue-600' :
                    'bg-gray-400 border-gray-500'
                  }`}></div>

                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center space-x-2 flex-wrap">
                        <span className="text-lg">{getEventIcon(event)}</span>
                        <span className={`font-medium ${
                          event.is_trigger ? 'text-red-700' :
                          event.priority === 'high' ? 'text-orange-700' :
                          'text-gray-900'
                        }`}>
                          {event.event_name}
                        </span>
                        {event.is_trigger && (
                          <span className="px-2 py-0.5 text-xs bg-red-200 text-red-800 rounded">
                            TRIGGER
                          </span>
                        )}
                        {event.label && !event.is_trigger && (
                          <span className={`px-2 py-0.5 text-xs rounded ${
                            event.priority === 'high' ? 'bg-orange-200 text-orange-800' :
                            event.priority === 'recon' ? 'bg-blue-200 text-blue-800' :
                            'bg-gray-200 text-gray-700'
                          }`}>
                            {event.label}
                          </span>
                        )}
                      </div>
                      <div className="mt-1 flex flex-wrap items-center gap-3 text-xs text-gray-500">
                        <span>🕐 {event.event_time ? new Date(event.event_time).toLocaleTimeString() : 'N/A'}</span>
                        <span>👤 {event.actor || 'Unknown'}</span>
                        {event.source_ip && <span>🌐 {event.source_ip}</span>}
                        {event.region && <span>🌍 {event.region}</span>}
                      </div>
                    </div>
                    <button
                      onClick={(e) => { e.stopPropagation(); toggleEvent(event.index); }}
                      className="text-gray-400 hover:text-gray-600 ml-2"
                    >
                      {expandedEvents.has(event.index) ? '−' : '+'}
                    </button>
                  </div>

                  {/* Expanded Details */}
                  {expandedEvents.has(event.index) && event.event_id && (
                    <div className="mt-2 pt-2 border-t border-gray-200">
                      <div className="text-xs text-gray-500">
                        <div><strong>Event ID:</strong> {event.event_id}</div>
                        {event.event_time && (
                          <div><strong>Full Time:</strong> {new Date(event.event_time).toLocaleString()}</div>
                        )}
                        {event.is_trigger && (
                          <div className="mt-1 text-red-600">🚨 This is the triggering event</div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default TimelineSection;