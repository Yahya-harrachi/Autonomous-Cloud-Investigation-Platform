// frontend/src/components/evidence/EvidenceSection.jsx
import React, { useState, useEffect } from 'react';
import EvidenceCard from './EvidenceCard';
import { getIncidentEvidence, batchVerifyEvidence } from '../../services/evidence';

const EvidenceSection = ({ incidentId }) => {
  const [evidence, setEvidence] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [verifyingAll, setVerifyingAll] = useState(false);
  const [autoVerify, setAutoVerify] = useState(true);

  useEffect(() => {
    if (incidentId) {
      loadEvidence();
    }
  }, [incidentId]);

  const loadEvidence = async () => {
    setLoading(true);
    try {
      const data = await getIncidentEvidence(incidentId);
      console.log('📊 Evidence API Response:', data);
      setEvidence(data || []);
    } catch (err) {
      setError(err.message);
      console.error('Error loading evidence:', err);
    } finally {
      setLoading(false);
    }
  };

  // ✅ Batch verify all evidence
  const handleBatchVerify = async () => {
    setVerifyingAll(true);
    try {
      const results = await batchVerifyEvidence(incidentId);
      console.log('📊 Batch verification results:', results);
      // Refresh evidence to show updated verification status
      await loadEvidence();
    } catch (err) {
      console.error('Batch verification failed:', err);
      setError('Failed to verify all evidence: ' + err.message);
    } finally {
      setVerifyingAll(false);
    }
  };

  // Get statistics
  const totalArtifacts = evidence.length;
  const completed = evidence.filter(e => e.collection_status === 'COMPLETED').length;
  const failed = evidence.filter(e => e.collection_status === 'FAILED').length;
  const pending = evidence.filter(e => e.collection_status === 'PENDING').length;
  
  // ✅ Get verification statistics
  const verifiedCount = evidence.filter(e => e.integrity_verified === true).length;
  const unverifiedCount = evidence.filter(e => e.integrity_verified === false && e.hash && e.hash !== 'N/A').length;
  const noHashCount = evidence.filter(e => !e.hash || e.hash === 'N/A').length;

  // Group evidence by type
  const groupedEvidence = evidence.reduce((acc, item) => {
    const type = item.artifact_type || 'Unknown';
    if (!acc[type]) acc[type] = [];
    acc[type].push(item);
    return acc;
  }, {});

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

  // Toggle auto-verify
  const toggleAutoVerify = () => {
    setAutoVerify(!autoVerify);
  };

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

  if (error) {
    return (
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="text-center py-4 text-red-600">
          ❌ Error loading evidence: {error}
        </div>
      </div>
    );
  }

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
            <div>
              <span className="text-sm text-blue-600">🔐 Verified</span>
              <div className="text-xl font-bold text-blue-600">{verifiedCount}</div>
            </div>
            {unverifiedCount > 0 && (
              <div>
                <span className="text-sm text-yellow-600">⚠️ Unverified</span>
                <div className="text-xl font-bold text-yellow-600">{unverifiedCount}</div>
              </div>
            )}
            {failed > 0 && (
              <div>
                <span className="text-sm text-red-600">❌ Failed</span>
                <div className="text-xl font-bold text-red-600">{failed}</div>
              </div>
            )}
          </div>
          
          <div className="flex items-center space-x-2">
            {/* Auto-verify toggle */}
            <button
              onClick={toggleAutoVerify}
              className={`px-2 py-1 text-xs rounded ${
                autoVerify 
                  ? 'bg-green-100 text-green-700' 
                  : 'bg-gray-100 text-gray-500'
              }`}
            >
              {autoVerify ? '🔐 Auto-Verify On' : '🔓 Auto-Verify Off'}
            </button>
            
            {/* Batch verify button */}
            {unverifiedCount > 0 && (
              <button
                onClick={handleBatchVerify}
                disabled={verifyingAll}
                className="px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {verifyingAll ? 'Verifying...' : `🔐 Verify All (${unverifiedCount})`}
              </button>
            )}
            
            <button
              onClick={loadEvidence}
              disabled={loading}
              className="px-3 py-1 text-sm bg-gray-100 text-gray-700 rounded hover:bg-gray-200 disabled:opacity-50"
            >
              {loading ? 'Loading...' : '🔄 Refresh'}
            </button>
          </div>
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
            <EvidenceCard 
              key={artifact.id} 
              artifact={artifact} 
              autoVerify={autoVerify}
            />
          ))}
        </div>
      ))}
    </div>
  );
};

export default EvidenceSection;