import React from 'react';

const SeverityBadge = ({ severity }) => {
  const severityColors = {
    CRITICAL: 'bg-red-100 text-red-800',
    HIGH: 'bg-orange-100 text-orange-800',
    MEDIUM: 'bg-yellow-100 text-yellow-800',
    LOW: 'bg-green-100 text-green-800',
  };

  const color = severityColors[severity] || 'bg-gray-100 text-gray-800';

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded-full ${color}`}>
      {severity}
    </span>
  );
};

export default SeverityBadge;