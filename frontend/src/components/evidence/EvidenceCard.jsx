// frontend/src/components/evidence/EvidenceCard.jsx
import React, { useState } from 'react';
import { verifyEvidence } from '../../services/evidence';

const EvidenceCard = ({ artifact }) => {
  const [verifying, setVerifying] = useState(false);
  const [verified, setVerified] = useState(artifact.integrity_verified);
  const [verificationResult, setVerificationResult] = useState(null);

  const handleVerify = async () => {
    setVerifying(true);
    try {
      const result = await verifyEvidence(artifact.id);
      setVerified(result.verified);
      setVerificationResult(result);
    } catch (error) {
      console.error('Verification failed:', error);
    } finally {
      setVerifying(false);
    }
  };

  // Get icon based on artifact type
  const getIcon = (type) => {
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

  // Get color based on status
  const getStatusColor = (status) => {
    const colors = {
      'COMPLETED': 'text-green-600 bg-green-50',
      'PARTIAL': 'text-yellow-600 bg-yellow-50',
      'FAILED': 'text-red-600 bg-red-50',
      'PENDING': 'text-blue-600 bg-blue-50',
      'COLLECTING': 'text-purple-600 bg-purple-50'
    };
    return colors[status] || 'text-gray-600 bg-gray-50';
  };

  // Get status badge
  const getStatusBadge = (status) => {
    const badges = {
      'COMPLETED': '✅ Completed',
      'PARTIAL': '⚠️ Partial',
      'FAILED': '❌ Failed',
      'PENDING': '⏳ Pending',
      'COLLECTING': '🔄 Collecting'
    };
    return badges[status] || status;
  };

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 bg-gray-50 border-b border-gray-200 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <span className="text-xl">{getIcon(artifact.artifact_type)}</span>
          <div>
            <h3 className="font-medium text-gray-900">{artifact.artifact_type}</h3>
            <p className="text-xs text-gray-500">
              Collected by {artifact.collector}
            </p>
          </div>
        </div>
        <div className="flex items-center space-x-2">
          <span className={`px-2 py-1 text-xs rounded-full ${getStatusColor(artifact.collection_status)}`}>
            {getStatusBadge(artifact.collection_status)}
          </span>
        </div>
      </div>

      {/* Content */}
      <div className="p-4">
        {/* Summary - different for each type */}
        {artifact.artifact_type === 'CloudTrailEvent' && (
          <CloudTrailSummary content={artifact.content} />
        )}
        
        {artifact.artifact_type === 'IAMUser' && (
          <IAMSummary content={artifact.content} />
        )}

        {/* Integrity Section */}
        <div className="mt-4 pt-4 border-t border-gray-200">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="text-sm text-gray-500">SHA-256:</span>
              <code className="text-xs bg-gray-100 px-2 py-1 rounded font-mono">
                {artifact.hash ? artifact.hash.substring(0, 16) + '...' : 'N/A'}
              </code>
            </div>
            
            <div className="flex items-center space-x-3">
              {/* Integrity Status */}
              {verified ? (
                <span className="text-green-600 text-sm flex items-center">
                  ✅ Integrity Verified
                </span>
              ) : (
                <span className="text-yellow-600 text-sm flex items-center">
                  ⚠️ Not Verified
                </span>
              )}
              
              {/* Verify Button */}
              <button
                onClick={handleVerify}
                disabled={verifying}
                className="px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
              >
                {verifying ? 'Verifying...' : 'Verify'}
              </button>
            </div>
          </div>

          {/* Verification Result */}
          {verificationResult && (
            <div className={`mt-2 p-2 rounded text-sm ${
              verificationResult.verified 
                ? 'bg-green-50 text-green-700' 
                : 'bg-red-50 text-red-700'
            }`}>
              {verificationResult.verified 
                ? '✅ Evidence integrity verified successfully' 
                : '❌ Integrity verification failed - Evidence may be tampered!'}
            </div>
          )}

          {/* Metadata */}
          <div className="mt-2 flex flex-wrap gap-2 text-xs text-gray-400">
            <span>Collected: {new Date(artifact.collected_at).toLocaleString()}</span>
            <span>•</span>
            <span>ID: {artifact.id.substring(0, 8)}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

// CloudTrail Summary Component
const CloudTrailSummary = ({ content }) => {
  const summary = content?.summary || {};
  const timeline = content?.timeline || [];
  const timeWindow = content?.time_window || {};

  return (
    <div className="space-y-2">
      <div className="grid grid-cols-3 gap-2">
        <div className="bg-blue-50 p-2 rounded">
          <div className="text-xs text-gray-500">Total Events</div>
          <div className="text-lg font-semibold">{summary.total_events || 0}</div>
        </div>
        <div className="bg-green-50 p-2 rounded">
          <div className="text-xs text-gray-500">Unique Actors</div>
          <div className="text-lg font-semibold">{summary.unique_actors?.length || 0}</div>
        </div>
        <div className="bg-purple-50 p-2 rounded">
          <div className="text-xs text-gray-500">Event Types</div>
          <div className="text-lg font-semibold">{summary.event_types?.length || 0}</div>
        </div>
      </div>

      {/* Timeline Preview */}
      {timeline.length > 0 && (
        <div className="mt-2">
          <div className="text-sm font-medium text-gray-700">Timeline</div>
          <div className="mt-1 max-h-32 overflow-y-auto space-y-1">
            {timeline.slice(0, 5).map((event, idx) => (
              <div key={idx} className="flex items-center space-x-2 text-xs">
                <span className="text-gray-400">
                  {event.event_time ? new Date(event.event_time).toLocaleTimeString() : 'N/A'}
                </span>
                <span className={event.is_trigger ? 'text-red-500 font-bold' : 'text-gray-600'}>
                  {event.is_trigger ? '🚨' : '•'} {event.event_name}
                </span>
                <span className="text-gray-400">by {event.actor || 'Unknown'}</span>
              </div>
            ))}
            {timeline.length > 5 && (
              <div className="text-xs text-gray-400">+ {timeline.length - 5} more events</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

// IAM Summary Component
const IAMSummary = ({ content }) => {
  const user = content?.user || {};
  const summary = content?.summary || {};
  const attachedPolicies = content?.attached_policies || [];
  const groups = content?.groups || [];
  const accessKeys = content?.access_keys || [];

  return (
    <div className="space-y-2">
      <div className="grid grid-cols-2 gap-2">
        <div className="bg-blue-50 p-2 rounded">
          <div className="text-xs text-gray-500">User</div>
          <div className="text-sm font-semibold">{user.user_name || 'N/A'}</div>
          <div className="text-xs text-gray-400">{user.user_id || 'N/A'}</div>
        </div>
        <div className="bg-green-50 p-2 rounded">
          <div className="text-xs text-gray-500">MFA Status</div>
          <div className="text-sm font-semibold">
            {user.mfa_active ? '✅ Enabled' : '❌ Disabled'}
          </div>
          <div className="text-xs text-gray-400">
            Created: {user.create_date ? new Date(user.create_date).toLocaleDateString() : 'N/A'}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-2">
        <div className="bg-purple-50 p-2 rounded">
          <div className="text-xs text-gray-500">Attached Policies</div>
          <div className="text-lg font-semibold">{summary.total_attached_policies || 0}</div>
        </div>
        <div className="bg-yellow-50 p-2 rounded">
          <div className="text-xs text-gray-500">Groups</div>
          <div className="text-lg font-semibold">{summary.total_groups || 0}</div>
        </div>
        <div className="bg-red-50 p-2 rounded">
          <div className="text-xs text-gray-500">Access Keys</div>
          <div className="text-lg font-semibold">{summary.total_access_keys || 0}</div>
        </div>
      </div>

      {/* Security Alerts */}
      {!user.mfa_active && (
        <div className="bg-red-50 border border-red-200 rounded p-2 text-xs text-red-700">
          ⚠️ MFA is not enabled for this user
        </div>
      )}
      
      {accessKeys.length > 0 && (
        <div className="bg-yellow-50 border border-yellow-200 rounded p-2 text-xs text-yellow-700">
          ⚠️ {accessKeys.length} access key(s) found
        </div>
      )}
    </div>
  );
};

export default EvidenceCard;