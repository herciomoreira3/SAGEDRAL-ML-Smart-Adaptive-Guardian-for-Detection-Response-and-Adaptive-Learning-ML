import React from 'react';

export function SeverityBadge({ severity }) {
  const sev = (severity || 'LOW').toUpperCase();

  const styles = {
    CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/40',
    HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/40',
    MEDIUM: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
    LOW: 'bg-blue-500/20 text-blue-400 border-blue-500/40',
  };

  const style = styles[sev] || styles.LOW;

  return (
    <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border ${style}`}>
      {sev}
    </span>
  );
}
