import React from 'react';
import { X, Ban, ThumbsUp, ThumbsDown } from 'lucide-react';
import { SeverityBadge } from './SeverityBadge';
import { useTranslation } from '../i18n/hook';

export function AlertDetailModal({ alert, onClose, onBlock, onFeedback }) {
  const { T } = useTranslation();
  if (!alert) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="glass-card w-full max-w-2xl overflow-hidden animate-in fade-in zoom-in duration-150">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <h3 className="text-lg font-bold text-slate-100">{T.modal_alert_details}</h3>
            <SeverityBadge severity={alert.severity} />
          </div>
          <button 
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-4 text-sm">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-xs text-slate-500 uppercase font-medium">{T.modal_alert_id}</p>
              <p className="font-mono text-xs text-slate-300 mt-1 break-all">{alert.alert_id}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500 uppercase font-medium">{T.modal_timestamp}</p>
              <p className="text-slate-300 mt-1">{new Date(alert.timestamp * 1000).toLocaleString()}</p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4 bg-slate-950/60 p-3.5 rounded-lg border border-slate-800">
            <div>
              <p className="text-xs text-slate-500 uppercase font-medium">{T.modal_src_ip_port}</p>
              <p className="font-mono text-blue-400 font-semibold mt-1">
                {alert.src_ip} : {alert.src_port || T.modal_na}
              </p>
            </div>
            <div>
              <p className="text-xs text-slate-500 uppercase font-medium">{T.modal_dst_ip_port}</p>
              <p className="font-mono text-slate-300 mt-1">
                {alert.dst_ip} : {alert.dst_port || T.modal_na}
              </p>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div>
              <p className="text-xs text-slate-500 uppercase font-medium">{T.modal_attack_type}</p>
              <p className="font-semibold text-slate-200 mt-1">{alert.attack_type}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500 uppercase font-medium">{T.modal_protocol}</p>
              <p className="font-mono text-slate-300 mt-1">{alert.protocol}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500 uppercase font-medium">{T.modal_action_taken}</p>
              <span className={`inline-block mt-1 font-semibold text-xs px-2 py-0.5 rounded ${
                alert.action_taken === 'BLOCKED' ? 'bg-red-500/20 text-red-400' : 'bg-amber-500/20 text-amber-400'
              }`}>
                {alert.action_taken}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4 border-t border-slate-800 pt-4">
            <div>
              <p className="text-xs text-slate-500 uppercase font-medium">{T.modal_hybrid_score}</p>
              <p className="text-lg font-bold text-slate-100 mt-1">{(alert.final_score * 100).toFixed(1)}%</p>
            </div>
            <div>
              <p className="text-xs text-slate-500 uppercase font-medium">{T.modal_ml_score}</p>
              <p className="text-lg font-bold text-blue-400 mt-1">
                {alert.ml_anomaly_score ? (alert.ml_anomaly_score * 100).toFixed(1) + '%' : T.modal_na}
              </p>
            </div>
          </div>

          {alert.signature_matched && alert.signature_matched.length > 0 && (
            <div>
              <p className="text-xs text-slate-500 uppercase font-medium mb-1.5">{T.modal_signatures}</p>
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

        <div className="p-4 border-t border-slate-800 bg-slate-950/40 flex flex-wrap justify-end gap-3">
          <button
            onClick={() => onFeedback?.(alert.alert_id, 'TRUE_POSITIVE')}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-emerald-600/20 text-emerald-400 text-xs"
          >
            <ThumbsUp className="w-3.5 h-3.5" />
            {T.modal_true_positive}
          </button>
          <button
            onClick={() => onFeedback?.(alert.alert_id, 'FALSE_POSITIVE')}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-amber-600/20 text-amber-400 text-xs"
          >
            <ThumbsDown className="w-3.5 h-3.5" />
            {T.modal_false_positive}
          </button>
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold text-slate-400 hover:text-slate-200 transition-colors"
          >
            {T.modal_close}
          </button>
          {alert.action_taken !== 'BLOCKED' && (
            <button
              onClick={() => onBlock(alert.src_ip)}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-red-600 hover:bg-red-700 text-white font-medium text-xs transition-colors"
            >
              <Ban className="w-3.5 h-3.5" />
              {T.modal_block_ip}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

export default AlertDetailModal;
