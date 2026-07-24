import React from 'react';
import { X, Ban, ShieldCheck } from 'lucide-react';
import { SeverityBadge } from './SeverityBadge';

export function AlertDetailModal({ alert, onClose, onBlock }) {
  if (!alert) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="glass-card w-full max-w-2xl overflow-hidden animate-in fade-in zoom-in duration-150">
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <h3 className="text-lg font-bold text-slate-100">Alert Details</h3>
            <SeverityBadge severity={alert.severity} />
          </div>
          <button 
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Content */}
        <div className="p-6 space-y-4 text-sm">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-xs text-slate-500 uppercase font-medium">Alert ID</p>
              <p className="font-mono text-xs text-slate-300 mt-1 break-all">{alert.alert_id}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500 uppercase font-medium">Timestamp</p>
              <p className="text-slate-300 mt-1">{new Date(alert.timestamp * 1000).toLocaleString()}</p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4 bg-slate-950/60 p-3.5 rounded-lg border border-slate-800">
            <div>
              <p className="text-xs text-slate-500 uppercase font-medium">Source IP : Port</p>
              <p className="font-mono text-blue-400 font-semibold mt-1">
                {alert.src_ip} : {alert.src_port || 'N/A'}
              </p>
            </div>
            <div>
              <p className="text-xs text-slate-500 uppercase font-medium">Destination IP : Port</p>
              <p className="font-mono text-slate-300 mt-1">
                {alert.dst_ip} : {alert.dst_port || 'N/A'}
              </p>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div>
              <p className="text-xs text-slate-500 uppercase font-medium">Attack Type</p>
              <p className="font-semibold text-slate-200 mt-1">{alert.attack_type}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500 uppercase font-medium">Protocol</p>
              <p className="font-mono text-slate-300 mt-1">{alert.protocol}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500 uppercase font-medium">Action Taken</p>
              <span className={`inline-block mt-1 font-semibold text-xs px-2 py-0.5 rounded ${
                alert.action_taken === 'BLOCKED' ? 'bg-red-500/20 text-red-400' : 'bg-amber-500/20 text-amber-400'
              }`}>
                {alert.action_taken}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4 border-t border-slate-800 pt-4">
            <div>
              <p className="text-xs text-slate-500 uppercase font-medium">Hybrid Final Score</p>
              <p className="text-lg font-bold text-slate-100 mt-1">{(alert.final_score * 100).toFixed(1)}%</p>
            </div>
            <div>
              <p className="text-xs text-slate-500 uppercase font-medium">ML Anomaly Score</p>
              <p className="text-lg font-bold text-blue-400 mt-1">
                {alert.ml_anomaly_score ? (alert.ml_anomaly_score * 100).toFixed(1) + '%' : 'N/A'}
              </p>
            </div>
          </div>

          {alert.signature_matched && alert.signature_matched.length > 0 && (
            <div>
              <p className="text-xs text-slate-500 uppercase font-medium mb-1">Matched Signatures</p>
              <div className="flex flex-wrap gap-1.5">
                {alert.signature_matched.map((sig, idx) => (
                  <span key={idx} className="font-mono text-xs px-2 py-0.5 bg-slate-800 text-blue-300 rounded border border-slate-700">
                    {sig}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Modal Actions */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/40 flex justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold text-slate-400 hover:text-slate-200 transition-colors"
          >
            Close
          </button>
          {alert.action_taken !== 'BLOCKED' && (
            <button
              onClick={() => onBlock(alert.src_ip)}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-red-600 hover:bg-red-700 text-white font-medium text-xs transition-colors"
            >
              <Ban className="w-3.5 h-3.5" />
              Block Source IP
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
