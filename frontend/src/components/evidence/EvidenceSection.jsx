// frontend/src/components/evidence/EvidenceSection.jsx
import React, { useState, useEffect } from 'react';
import EvidenceCard from './EvidenceCard';
import { getIncidentEvidence } from '../../services/evidence';

const EvidenceSection = ({ incidentId }) => {
  const [evidence, setEvidence] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (incidentId) {
      loadEvidence();
    }
  }, [incidentId]);

  const loadEvidence = async () => {
    setLoading(true);  // ✅ Set loading BEFORE API call
    try {
      const data = await getIncidentEvidence(incidentId);
      console.log('📊 Evidence API Response:', data);
      setEvidence(data || []);
    } catch (err) {
      setError(err.message);
      console.error('Error loading evidence:', err);
    } finally {
      setLoading(false);  // ✅ Set loading AFTER API call
    }
  };

  // Get statistics
  const totalArtifacts = evidence.length;
  const completed = evidence.filter(e => e.collection_status === 'COMPLETED').length;
  const failed = evidence.filter(e => e.collection_status === 'FAILED').length;
  const pending = evidence.filter(e => e.collection_status === 'PENDING').length;

  // Group evidence by type
  const groupedEvidence = evidence.reduce((acc, item) => {
    const type = item.artifact_type || 'Unknown';
    if (!acc[type]) acc[type] = [];
    acc[type].push(item);
    return acc;
  }, {});

  // ✅ Get icon for each type
  const getTypeIcon = (type) => {
    const icons = {
      'CloudTrailEvent': '📊',
      'IAMUser': '👤',
      'IAMPolicy': '📋',
      'IAMRole': '🎭',
      'S3Bucket': '🪣',
      'EC2Instance': '🖥️'
    };
    return icons[type] || '📦';
  };

  // ✅ LOADING STATE - Show spinner
  if (loading) {
    return (
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex flex-col items-center justify-center py-8">
          <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-blue-600"></div>
          <span className="mt-3 text-gray-600">Loading evidence artifacts...</span>
          <span className="text-xs text-gray-400 mt-1">Collecting data from AWS</span>
        </div>
      </div>
    );
  }

  // ✅ ERROR STATE
  if (error) {
    return (
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="text-center py-4 text-red-600">
          ❌ Error loading evidence: {error}
        </div>
      </div>
    );
  }

  // ✅ EMPTY STATE - Only show if not loading and no evidence
  if (evidence.length === 0) {
    return (
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="text-center py-8 text-gray-500">
          <div className="text-4xl mb-2">📋</div>
          <p>No evidence collected for this incident</p>
          <p className="text-sm text-gray-400 mt-1">
            Evidence is automatically collected for high-severity incidents
          </p>
        </div>
      </div>
    );
  }

  // ✅ EVIDENCE DISPLAY
  return (
    <div className="space-y-4">
      {/* Stats Bar */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center space-x-6 flex-wrap gap-2">
            <div>
              <span className="text-sm text-gray-500">Total Evidence</span>
              <div className="text-xl font-bold">{totalArtifacts}</div>
            </div>
            <div>
              <span className="text-sm text-green-600">✅ Completed</span>
              <div className="text-xl font-bold text-green-600">{completed}</div>
            </div>
            {failed > 0 && (
              <div>
                <span className="text-sm text-red-600">❌ Failed</span>
                <div className="text-xl font-bold text-red-600">{failed}</div>
              </div>
            )}
            {pending > 0 && (
              <div>
                <span className="text-sm text-yellow-600">⏳ Pending</span>
                <div className="text-xl font-bold text-yellow-600">{pending}</div>
              </div>
            )}
          </div>
          
          <button
            onClick={loadEvidence}
            disabled={loading}
            className="px-3 py-1 text-sm bg-gray-100 text-gray-700 rounded hover:bg-gray-200 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Loading...' : '🔄 Refresh'}
          </button>
        </div>
      </div>

      {/* Evidence Cards Grouped by Type */}
      {Object.entries(groupedEvidence).map(([type, artifacts]) => (
        <div key={type} className="space-y-2">
          <div className="flex items-center space-x-2">
            <span className="text-lg">{getTypeIcon(type)}</span>
            <h4 className="text-sm font-medium text-gray-700">
              {type} ({artifacts.length})
            </h4>
          </div>
          {artifacts.map((artifact) => (
            <EvidenceCard key={artifact.id} artifact={artifact} />
          ))}
        </div>
      ))}
    </div>
  );
};

export default EvidenceSection;