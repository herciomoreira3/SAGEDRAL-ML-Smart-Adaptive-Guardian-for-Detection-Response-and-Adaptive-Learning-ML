import React, { useEffect } from 'react';
import { X, AlertTriangle } from 'lucide-react';
import { useTranslation } from '../i18n/hook';

export function ConfirmDialog({
  isOpen,
  title,
  body,
  confirmLabel,
  cancelLabel,
  onConfirm,
  onCancel,
  danger = true,
  icon: Icon,
}) {
  const { T } = useTranslation();
  const finalConfirmLabel = confirmLabel || (danger ? T.confirm_yes : T.confirm_save_yes);
  const finalCancelLabel = cancelLabel || T.confirm_no;
  const DialogIcon = Icon || AlertTriangle;

  useEffect(() => {
    if (!isOpen) return;
    const handleEsc = (e) => {
      if (e.key === 'Escape') onCancel?.();
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [isOpen, onCancel]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
      <div
        className="absolute inset-0 bg-black/70 backdrop-blur-sm"
        onClick={onCancel}
      />
      <div className="relative glass-card w-full max-w-md overflow-hidden animate-in fade-in zoom-in duration-150">
        <div className="p-5 border-b border-slate-800 flex items-start gap-3">
          <div className={`p-2.5 rounded-xl border shrink-0 ${
            danger
              ? 'bg-red-500/10 border-red-500/30 text-red-400'
              : 'bg-blue-500/10 border-blue-500/30 text-blue-400'
          }`}>
            <DialogIcon className="w-5 h-5" />
          </div>
          <div className="flex-1 pt-0.5">
            <h3 className="text-base font-bold text-slate-100">{title}</h3>
          </div>
          <button
            onClick={onCancel}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors shrink-0"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-5">
          <p className="text-sm text-slate-300 leading-relaxed">{body}</p>
        </div>

        <div className="p-4 border-t border-slate-800 bg-slate-950/40 flex justify-end gap-2.5">
          <button
            onClick={onCancel}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold text-xs border border-slate-700 transition-colors"
          >
            {finalCancelLabel}
          </button>
          <button
            onClick={onConfirm}
            className={`px-4 py-2 rounded-lg font-semibold text-xs text-white transition-colors ${
              danger
                ? 'bg-red-600 hover:bg-red-700'
                : 'bg-blue-600 hover:bg-blue-700'
            }`}
          >
            {finalConfirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

export default ConfirmDialog;
