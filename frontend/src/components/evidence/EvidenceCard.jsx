// frontend/src/components/evidence/EvidenceCard.jsx
import React, { useState, useEffect } from 'react';
import { verifyEvidence } from '../../services/evidence';

// ============================================================
// CLOUD TRAIL SUMMARY COMPONENT
// ============================================================
const CloudTrailSummary = ({ content }) => {
  const summary = content?.summary || {};
  const timeline = content?.timeline || [];
  const patterns = content?.patterns || [];
  const uniqueIPs = timeline.reduce((acc, event) => {
    const ip = event.source_ip;
    if (ip && ip !== 'unknown' && ip !== 'N/A') {
      if (!acc[ip]) acc[ip] = [];
      acc[ip].push(event);
    }
    return acc;
  }, {});
  
  return (
    <div className="space-y-3">
      {/* Stats */}
      <div className="grid grid-cols-3 gap-2">
        <div className="bg-blue-50 p-2 rounded">
          <div className="text-xs text-gray-500">Total Events</div>
          <div className="text-lg font-semibold">{summary.total_events || 0}</div>
        </div>
        <div className="bg-red-50 p-2 rounded">
          <div className="text-xs text-gray-500">High Priority</div>
          <div className="text-lg font-semibold text-red-600">{summary.high_priority_events || 0}</div>
        </div>
        <div className="bg-purple-50 p-2 rounded">
          <div className="text-xs text-gray-500">Patterns Found</div>
          <div className="text-lg font-semibold text-purple-600">{summary.patterns_found || 0}</div>
        </div>
      </div>

      {/* Security Alerts */}
      {summary.security_alerts && summary.security_alerts.length > 0 && (
        <div className="bg-red-50 border border-red-200 rounded p-2">
          <div className="text-xs font-bold text-red-700">⚠️ Security Alerts</div>
          {summary.security_alerts.map((alert, idx) => (
            <div key={idx} className="mt-1 text-xs text-red-600">
              • {alert.description}
              {alert.recommendation && (
                <div className="text-gray-600">  💡 {alert.recommendation}</div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Patterns */}
      {patterns && patterns.length > 0 && (
        <div className="bg-yellow-50 border border-yellow-200 rounded p-2">
          <div className="text-xs font-bold text-yellow-700">🔍 Attack Patterns Detected</div>
          {patterns.map((pattern, idx) => (
            <div key={idx} className="mt-1 text-xs text-yellow-700">
              • {pattern.description}
              <span className={`ml-2 px-1 rounded ${
                pattern.severity === 'critical' ? 'bg-red-200 text-red-800' :
                pattern.severity === 'high' ? 'bg-orange-200 text-orange-800' :
                'bg-yellow-200 text-yellow-800'
              }`}>
                {pattern.severity.toUpperCase()}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Threat Intelligence */}
      {Object.keys(uniqueIPs).length > 0 && (
        <div className="border border-gray-200 rounded p-2">
          <div className="text-xs font-medium text-gray-700">🌐 Threat Intelligence</div>
          {Object.entries(uniqueIPs).map(([ip, events]) => {
            const threatData = events[0]?.threat_intel;
            if (!threatData) {
              return (
                <div key={ip} className="mt-1 text-xs flex justify-between">
                  <span className="text-gray-500">{ip}</span>
                  <span className="text-green-600">✅ Clean</span>
                </div>
              );
            }
            
            const score = threatData.abuse_score;
            const emoji = score >= 75 ? '🔴' : score >= 50 ? '🟠' : score >= 25 ? '🟡' : '🔵';
            const level = score >= 75 ? 'Malicious' : score >= 50 ? 'Suspicious' : score >= 25 ? 'Low Risk' : 'Clean';
            
            return (
              <div key={ip} className="mt-1 text-xs">
                <div className="flex justify-between items-center">
                  <span className="font-mono">{ip}</span>
                  <span className={`px-2 py-0.5 rounded ${
                    score >= 50 ? 'bg-red-100 text-red-700' :
                    score >= 25 ? 'bg-yellow-100 text-yellow-700' :
                    'bg-green-100 text-green-700'
                  }`}>
                    {emoji} {level} ({score}/100)
                  </span>
                </div>
                {threatData.total_reports > 0 && (
                  <div className="text-gray-400">
                    {threatData.total_reports} reports • {threatData.country_name || 'Unknown'} • {threatData.isp || 'Unknown ISP'}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Timeline */}
      {timeline && timeline.length > 0 && (
        <div>
          <div className="text-sm font-medium text-gray-700 flex items-center justify-between">
            <span>🕐 Investigation Timeline</span>
            <span className="text-xs text-gray-400">{timeline.length} events</span>
          </div>
          <div className="mt-1 max-h-48 overflow-y-auto space-y-1 border border-gray-100 rounded p-2">
            {timeline.map((event, idx) => {
              const isTrigger = event.priority === 'trigger';
              const isHigh = event.priority === 'high';
              const isRecon = event.priority === 'recon';
              
              let bgColor = 'bg-gray-50';
              let borderColor = 'border-gray-200';
              if (isTrigger) {
                bgColor = 'bg-red-50';
                borderColor = 'border-red-300';
              } else if (isHigh) {
                bgColor = 'bg-orange-50';
                borderColor = 'border-orange-200';
              } else if (isRecon) {
                bgColor = 'bg-blue-50';
                borderColor = 'border-blue-200';
              }
              
              return (
                <div 
                  key={idx} 
                  className={`flex items-center justify-between text-xs p-1 rounded border ${bgColor} ${borderColor}`}
                >
                  <div className="flex items-center space-x-2 flex-1">
                    <span>{event.icon || '•'}</span>
                    <span className="text-gray-400 w-20">
                      {event.event_time ? new Date(event.event_time).toLocaleTimeString() : 'N/A'}
                    </span>
                    <span className={`font-medium ${
                      isTrigger ? 'text-red-700' :
                      isHigh ? 'text-orange-700' :
                      'text-gray-700'
                    }`}>
                      {event.event_name}
                    </span>
                    <span className="text-gray-400">by {event.actor || 'Unknown'}</span>
                  </div>
                  {event.label && (
                    <span className={`text-xs px-1 rounded ${
                      isTrigger ? 'bg-red-200 text-red-800' :
                      isHigh ? 'bg-orange-200 text-orange-800' :
                      'bg-blue-200 text-blue-800'
                    }`}>
                      {event.label}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

// ============================================================
// IAM USER SUMMARY COMPONENT
// ============================================================
const IAMSummary = ({ content }) => {
  const user = content?.user || {};
  const summary = content?.summary || {};
  const accessKeys = content?.access_keys || [];

  return (
    <div className="space-y-2">
      <div className="grid grid-cols-2 gap-2">
        <div className="bg-blue-50 p-2 rounded">
          <div className="text-xs text-gray-500">User</div>
          <div className="text-sm font-semibold">{user.user_name || 'N/A'}</div>
          <div className="text-xs text-gray-400">{user.user_id || 'N/A'}</div>
        </div>
        <div className={`p-2 rounded ${user.mfa_active ? 'bg-green-50' : 'bg-red-50'}`}>
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
          ⚠️ MFA is not enabled for this user - Security risk!
        </div>
      )}
      
      {accessKeys && accessKeys.length > 1 && (
        <div className="bg-yellow-50 border border-yellow-200 rounded p-2 text-xs text-yellow-700">
          ⚠️ {accessKeys.length} access key(s) found - Review active keys
        </div>
      )}

      {/* Access Keys Details */}
      {accessKeys && accessKeys.length > 0 && (
        <div className="border border-gray-200 rounded p-2">
          <div className="text-xs font-medium text-gray-700">🔑 Access Keys</div>
          {accessKeys.map((key, idx) => (
            <div key={idx} className="mt-1 text-xs flex justify-between">
              <span className="text-gray-500">{key.access_key_id}</span>
              <span className={key.status === 'Active' ? 'text-green-600' : 'text-gray-400'}>
                {key.status}
              </span>
              <span className="text-gray-400">
                Created: {key.create_date ? new Date(key.create_date).toLocaleDateString() : 'N/A'}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// ============================================================
// IAM POLICY SUMMARY COMPONENT
// ============================================================
const IAMPolicySummary = ({ content }) => {
  const policies = content?.policies || [];
  const summary = content?.summary || {};
  const securityAnalysis = content?.security_analysis || {};
  
  const highRisk = securityAnalysis?.high_risk_findings || [];
  const mediumRisk = securityAnalysis?.medium_risk_findings || [];
  
  if (policies.length === 0) {
    return (
      <div className="text-sm text-gray-500">
        No policies found in this incident
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Stats */}
      <div className="grid grid-cols-3 gap-2">
        <div className="bg-purple-50 p-2 rounded">
          <div className="text-xs text-gray-500">Total Policies</div>
          <div className="text-lg font-semibold">{summary.total_policies || 0}</div>
        </div>
        <div className="bg-red-50 p-2 rounded">
          <div className="text-xs text-gray-500">High Risk</div>
          <div className="text-lg font-semibold text-red-600">{highRisk.length}</div>
        </div>
        <div className="bg-yellow-50 p-2 rounded">
          <div className="text-xs text-gray-500">Medium Risk</div>
          <div className="text-lg font-semibold text-yellow-600">{mediumRisk.length}</div>
        </div>
      </div>

      {/* Policy List */}
      {policies.map((policy, idx) => (
        <div key={idx} className="border border-gray-200 rounded p-3">
          <div className="flex items-center justify-between">
            <div className="flex-1 min-w-0">
              <span className="font-medium text-sm">{policy.policy_name}</span>
              <div className="text-xs text-gray-400 truncate">{policy.arn}</div>
            </div>
            {policy.summary?.has_administrator_access && (
              <span className="ml-2 px-2 py-1 text-xs bg-red-100 text-red-700 rounded-full whitespace-nowrap">
                🔴 Admin
              </span>
            )}
          </div>
          
          <div className="mt-2 flex flex-wrap gap-2 text-xs text-gray-500">
            <span>Attachments: {policy.attachment_count || 0}</span>
            {policy.is_attachable && <span>• Attachable</span>}
            <span>• Statements: {policy.summary?.statement_count || 0}</span>
          </div>

          {/* Security Findings for this policy */}
          {policy.security_analysis && policy.security_analysis.length > 0 && (
            <div className="mt-2 space-y-1">
              {policy.security_analysis.map((finding, fi) => (
                <div 
                  key={fi} 
                  className={`text-xs p-1 rounded ${
                    finding.severity === 'high' ? 'bg-red-50 text-red-700' :
                    finding.severity === 'medium' ? 'bg-yellow-50 text-yellow-700' :
                    'bg-blue-50 text-blue-700'
                  }`}
                >
                  {finding.severity === 'high' ? '🔴' : finding.severity === 'medium' ? '🟠' : '🔵'} 
                  {finding.description}
                </div>
              ))}
            </div>
          )}
        </div>
      ))}

      {/* Security Findings Summary */}
      {highRisk.length > 0 && (
        <div className="bg-red-50 border border-red-200 rounded p-2 text-xs text-red-700">
          <div className="font-bold">⚠️ High Risk Findings:</div>
          {highRisk.map((finding, idx) => (
            <div key={idx} className="mt-1">
              • {finding.description}
              {finding.recommendation && (
                <div className="text-gray-600">  💡 {finding.recommendation}</div>
              )}
            </div>
          ))}
        </div>
      )}

      {mediumRisk.length > 0 && (
        <div className="bg-yellow-50 border border-yellow-200 rounded p-2 text-xs text-yellow-700">
          <div className="font-bold">🟠 Medium Risk Findings:</div>
          {mediumRisk.map((finding, idx) => (
            <div key={idx} className="mt-1">
              • {finding.description}
              {finding.recommendation && (
                <div className="text-gray-600">  💡 {finding.recommendation}</div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// ============================================================
// IAM ROLE SUMMARY COMPONENT
// ============================================================
const IAMRoleSummary = ({ content }) => {
  const roles = content?.roles || [];
  const summary = content?.summary || {};
  
  if (!roles || roles.length === 0) {
    return (
      <div className="text-sm text-gray-500">
        No IAM roles found for this incident
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Stats */}
      <div className="grid grid-cols-3 gap-2">
        <div className="bg-purple-50 p-2 rounded">
          <div className="text-xs text-gray-500">Total Roles</div>
          <div className="text-lg font-semibold">{summary.total_roles || 0}</div>
        </div>
        <div className="bg-red-50 p-2 rounded">
          <div className="text-xs text-gray-500">Admin Access</div>
          <div className="text-lg font-semibold text-red-600">{summary.roles_with_admin || 0}</div>
        </div>
        <div className="bg-blue-50 p-2 rounded">
          <div className="text-xs text-gray-500">Has Trust Policy</div>
          <div className="text-lg font-semibold text-blue-600">{summary.roles_with_trust || 0}</div>
        </div>
      </div>

      {/* Role List */}
      {roles.map((role, idx) => (
        <div key={idx} className="border border-gray-200 rounded p-3">
          <div className="flex items-center justify-between">
            <div className="flex-1 min-w-0">
              <span className="font-medium text-sm">{role.role_name || 'Unknown'}</span>
              <div className="text-xs text-gray-400 truncate">{role.arn || 'N/A'}</div>
            </div>
            {role.summary?.has_administrator_access && (
              <span className="ml-2 px-2 py-1 text-xs bg-red-100 text-red-700 rounded-full whitespace-nowrap">
                🔴 Admin
              </span>
            )}
          </div>
          
          <div className="mt-2 flex flex-wrap gap-2 text-xs text-gray-500">
            <span>Attached Policies: {role.summary?.attached_policy_count || 0}</span>
            <span>• Inline Policies: {role.summary?.inline_policy_count || 0}</span>
            {role.max_session_duration && (
              <span>• Session: {role.max_session_duration}s</span>
            )}
          </div>

          {/* Trust Policy */}
          {role.trust_policy && (
            <div className="mt-2 bg-blue-50 border border-blue-200 rounded p-2">
              <div className="text-xs font-medium text-blue-700">🔐 Trust Policy</div>
              <div className="text-xs text-blue-600 mt-1 font-mono">
                {JSON.stringify(role.trust_policy, null, 2).substring(0, 200)}
                {JSON.stringify(role.trust_policy, null, 2).length > 200 && '...'}
              </div>
            </div>
          )}

          {/* Attached Policies */}
          {role.attached_policies && role.attached_policies.length > 0 && (
            <div className="mt-2">
              <div className="text-xs font-medium text-gray-700">📋 Attached Policies</div>
              {role.attached_policies.map((policy, pi) => (
                <div key={pi} className="mt-1 text-xs text-gray-600">
                  • {policy.policy_name}
                  {policy.summary?.has_administrator_access && (
                    <span className="ml-2 text-red-600">(Admin)</span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
};



// ============================================================
// S3 BUCKET SUMMARY COMPONENT
// ============================================================
const S3Summary = ({ content }) => {
  const bucket = content?.bucket || {};
  const summary = content?.summary || {};
  const findings = content?.security_findings || [];
  
  if (!bucket || !bucket.bucket_name) {
    return (
      <div className="text-sm text-gray-500">
        No S3 bucket found in this incident
      </div>
    );
  }

  const criticalFindings = findings.filter(f => f.severity === 'critical');
  const highFindings = findings.filter(f => f.severity === 'high');

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-2">
        <div className="bg-blue-50 p-2 rounded">
          <div className="text-xs text-gray-500">Bucket</div>
          <div className="text-sm font-semibold">{bucket.bucket_name}</div>
          <div className="text-xs text-gray-400">{bucket.region || 'N/A'}</div>
        </div>
        <div className={`p-2 rounded ${bucket.is_public ? 'bg-red-50' : 'bg-green-50'}`}>
          <div className="text-xs text-gray-500">Public Access</div>
          <div className="text-sm font-semibold">
            {bucket.is_public ? '🔴 Public' : '🟢 Private'}
          </div>
          <div className="text-xs text-gray-400">
            Created: {bucket.creation_date ? new Date(bucket.creation_date).toLocaleDateString() : 'N/A'}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-2">
        <div className="bg-purple-50 p-2 rounded">
          <div className="text-xs text-gray-500">Security Findings</div>
          <div className="text-lg font-semibold text-red-600">{findings.length}</div>
        </div>
        <div className="bg-red-50 p-2 rounded">
          <div className="text-xs text-gray-500">Critical</div>
          <div className="text-lg font-semibold text-red-700">{criticalFindings.length}</div>
        </div>
        <div className="bg-orange-50 p-2 rounded">
          <div className="text-xs text-gray-500">High</div>
          <div className="text-lg font-semibold text-orange-700">{highFindings.length}</div>
        </div>
      </div>

      {/* Security Findings */}
      {findings.length > 0 && (
        <div className="space-y-1">
          {findings.map((finding, idx) => (
            <div 
              key={idx} 
              className={`text-xs p-1 rounded ${
                finding.severity === 'critical' ? 'bg-red-50 text-red-700' :
                finding.severity === 'high' ? 'bg-orange-50 text-orange-700' :
                finding.severity === 'medium' ? 'bg-yellow-50 text-yellow-700' :
                'bg-blue-50 text-blue-700'
              }`}
            >
              {finding.severity === 'critical' ? '🔴' : 
               finding.severity === 'high' ? '🟠' : 
               finding.severity === 'medium' ? '🟡' : '🔵'} 
              {finding.description}
              {finding.recommendation && (
                <div className="text-gray-600 text-xs">💡 {finding.recommendation}</div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// ============================================================
// SECURITY GROUP SUMMARY COMPONENT
// ============================================================
const SecurityGroupSummary = ({ content }) => {
  const sg = content?.security_group || {};
  const summary = content?.summary || {};
  const findings = content?.security_findings || [];
  
  if (!sg || !sg.group_id) {
    return (
      <div className="text-sm text-gray-500">
        No security group found in this incident
      </div>
    );
  }

  const inboundRules = sg.inbound_rules || [];
  const outboundRules = sg.outbound_rules || [];

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-2">
        <div className="bg-blue-50 p-2 rounded">
          <div className="text-xs text-gray-500">Security Group</div>
          <div className="text-sm font-semibold">{sg.group_name || 'N/A'}</div>
          <div className="text-xs text-gray-400">{sg.group_id}</div>
        </div>
        <div className="bg-purple-50 p-2 rounded">
          <div className="text-xs text-gray-500">VPC</div>
          <div className="text-sm font-semibold">{sg.vpc_id || 'N/A'}</div>
          <div className="text-xs text-gray-400">
            {sg.instances?.length || 0} instances using this SG
          </div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-2">
        <div className="bg-green-50 p-2 rounded">
          <div className="text-xs text-gray-500">Inbound Rules</div>
          <div className="text-lg font-semibold">{inboundRules.length}</div>
        </div>
        <div className="bg-blue-50 p-2 rounded">
          <div className="text-xs text-gray-500">Outbound Rules</div>
          <div className="text-lg font-semibold">{outboundRules.length}</div>
        </div>
        <div className="bg-red-50 p-2 rounded">
          <div className="text-xs text-gray-500">Security Findings</div>
          <div className="text-lg font-semibold text-red-600">{findings.length}</div>
        </div>
      </div>

      {/* Inbound Rules Preview */}
      {inboundRules.length > 0 && (
        <div className="border border-gray-200 rounded p-2">
          <div className="text-xs font-medium text-gray-700">📥 Inbound Rules</div>
          {inboundRules.slice(0, 5).map((rule, idx) => (
            <div key={idx} className="mt-1 text-xs flex justify-between">
              <span>
                {rule.protocol === '-1' ? 'All' : rule.protocol}
                {rule.from_port && rule.to_port && ` (${rule.from_port}-${rule.to_port})`}
              </span>
              <span className="text-gray-500">
                {rule.sources?.map(s => s.cidr || s.group_id || s.type).join(', ')}
              </span>
            </div>
          ))}
          {inboundRules.length > 5 && (
            <div className="text-xs text-gray-400">+ {inboundRules.length - 5} more rules</div>
          )}
        </div>
      )}

      {/* Security Findings */}
      {findings.length > 0 && (
        <div className="space-y-1">
          {findings.map((finding, idx) => (
            <div 
              key={idx} 
              className={`text-xs p-1 rounded ${
                finding.severity === 'critical' ? 'bg-red-50 text-red-700' :
                finding.severity === 'high' ? 'bg-orange-50 text-orange-700' :
                finding.severity === 'medium' ? 'bg-yellow-50 text-yellow-700' :
                'bg-blue-50 text-blue-700'
              }`}
            >
              {finding.severity === 'critical' ? '🔴' : 
               finding.severity === 'high' ? '🟠' : 
               finding.severity === 'medium' ? '🟡' : '🔵'} 
              {finding.description}
              {finding.recommendation && (
                <div className="text-gray-600 text-xs">💡 {finding.recommendation}</div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};


// ============================================================
// MAIN EVIDENCE CARD COMPONENT - WITH AUTO-VERIFY
// ============================================================
const EvidenceCard = ({ artifact, autoVerify = true }) => {
  const [verifying, setVerifying] = useState(false);
  const [verified, setVerified] = useState(artifact.integrity_verified || false);
  const [verificationResult, setVerificationResult] = useState(null);
  const [autoVerified, setAutoVerified] = useState(false);

  // ✅ Auto-verify on mount if not already verified
  useEffect(() => {
    if (autoVerify && !artifact.integrity_verified && !autoVerified) {
      // Only auto-verify if hash exists
      if (artifact.hash && artifact.hash !== 'N/A') {
        const timer = setTimeout(() => {
          handleVerify(true);
        }, 500);
        return () => clearTimeout(timer);
      }
    }
  }, []);

  const handleVerify = async (silent = false) => {
    if (!artifact.hash || artifact.hash === 'N/A') {
      if (!silent) {
        setVerificationResult({
          verified: false,
          message: 'No hash available to verify'
        });
      }
      return;
    }

    setVerifying(true);
    try {
      const result = await verifyEvidence(artifact.id);
      setVerified(result.verified);
      setVerificationResult(result);
      setAutoVerified(true);
      
      if (!silent) {
        console.log(`🔐 Verification result for ${artifact.artifact_type}:`, result.verified ? '✅ Verified' : '❌ Failed');
      }
    } catch (error) {
      console.error('Verification failed:', error);
      if (!silent) {
        setVerificationResult({
          verified: false,
          message: 'Verification service error'
        });
      }
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

  // ✅ Get verification status display
  const getVerificationDisplay = () => {
    if (verifying) {
      return { text: 'Verifying...', color: 'text-blue-600', icon: '🔄' };
    }
    if (verified) {
      return { text: '✅ Verified', color: 'text-green-600', icon: '✅' };
    }
    if (artifact.hash && artifact.hash !== 'N/A') {
      return { text: '⚠️ Not Verified', color: 'text-yellow-600', icon: '⚠️' };
    }
    return { text: 'No Hash', color: 'text-gray-400', icon: '⚪' };
  };

  const verifyDisplay = getVerificationDisplay();

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

        {artifact.artifact_type === 'IAMPolicy' && (
          <IAMPolicySummary content={artifact.content} />
        )}

        {artifact.artifact_type === 'IAMRole' && (
          <IAMRoleSummary content={artifact.content} />
        )}

        {artifact.artifact_type === 'S3Bucket' && (
          <S3Summary content={artifact.content} />
        )}

        {artifact.artifact_type === 'SecurityGroup' && (
          <SecurityGroupSummary content={artifact.content} />
        )}

        {/* Integrity Section - Enhanced */}
        <div className="mt-4 pt-4 border-t border-gray-200">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center space-x-2 min-w-0">
              <span className="text-sm text-gray-500 whitespace-nowrap">SHA-256:</span>
              <code className="text-xs bg-gray-100 px-2 py-1 rounded font-mono truncate max-w-[200px]">
                {artifact.hash ? artifact.hash.substring(0, 16) + '...' : 'N/A'}
              </code>
            </div>
            
            <div className="flex items-center space-x-3 flex-wrap gap-2">
              {/* ✅ Enhanced Verification Status */}
              <div className={`flex items-center space-x-1 text-sm ${verifyDisplay.color}`}>
                <span>{verifyDisplay.icon}</span>
                <span>{verifyDisplay.text}</span>
                {verifying && (
                  <span className="ml-1 text-xs text-gray-400">(calculating...)</span>
                )}
              </div>
              
              {/* Verify Button */}
              <button
                onClick={() => handleVerify(false)}
                disabled={verifying || !artifact.hash || artifact.hash === 'N/A'}
                className={`px-3 py-1 text-sm rounded disabled:opacity-50 disabled:cursor-not-allowed ${
                  verified 
                    ? 'bg-green-100 text-green-700 hover:bg-green-200' 
                    : 'bg-blue-600 text-white hover:bg-blue-700'
                }`}
              >
                {verifying ? 'Verifying...' : verified ? '✅ Re-verify' : 'Verify'}
              </button>
            </div>
          </div>

          {/* ✅ Auto-verify badge */}
          {autoVerified && !verifying && (
            <div className="mt-1 text-xs text-green-600 flex items-center">
              <span className="mr-1">✅</span>
              Auto-verified on load
            </div>
          )}

          {/* Verification Result - Enhanced */}
          {verificationResult && (
            <div className={`mt-2 p-2 rounded text-sm border ${
              verificationResult.verified 
                ? 'bg-green-50 text-green-700 border-green-200' 
                : 'bg-red-50 text-red-700 border-red-200'
            }`}>
              <div className="flex items-start">
                <span className="mr-2">{verificationResult.verified ? '✅' : '❌'}</span>
                <div>
                  <div className="font-medium">
                    {verificationResult.verified 
                      ? 'Evidence integrity verified successfully' 
                      : 'Integrity verification failed - Evidence may be tampered!'}
                  </div>
                  {verificationResult.message && (
                    <div className="text-xs mt-1 opacity-75">
                      {verificationResult.message}
                    </div>
                  )}
                  {verificationResult.verified && verificationResult.verified_at && (
                    <div className="text-xs mt-1 opacity-75">
                      Verified at: {new Date(verificationResult.verified_at).toLocaleString()}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Metadata */}
          <div className="mt-2 flex flex-wrap gap-2 text-xs text-gray-400">
            <span>Collected: {artifact.collected_at ? new Date(artifact.collected_at).toLocaleString() : 'N/A'}</span>
            <span>•</span>
            <span>ID: {artifact.id ? artifact.id.substring(0, 8) : 'N/A'}</span>
            {artifact.extra_data?.region && (
              <>
                <span>•</span>
                <span>Region: {artifact.extra_data.region}</span>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default EvidenceCard;