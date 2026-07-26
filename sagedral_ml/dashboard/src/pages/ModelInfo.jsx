import React, { useEffect, useState } from 'react';
import { getModelInfo, getModelDrift } from '../api/client';
import { useTranslation } from '../i18n/hook';
import { BrainCircuit, CheckCircle2, Cpu } from 'lucide-react';

export function ModelInfo() {
  const { T } = useTranslation();
  const [modelInfo, setModelInfo] = useState(null);
  const [drift, setDrift] = useState(null);

  useEffect(() => {
    getModelInfo().then(setModelInfo).catch(console.error);
    getModelDrift().then(setDrift).catch(() => setDrift(null));
  }, []);

  if (!modelInfo) {
    return <div className="text-slate-400 text-xs p-6">{T.model_loading}</div>;
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-100">{T.model_title}</h1>
        <p className="text-xs text-slate-400 mt-1">{T.model_subtitle}</p>
      </div>

      {drift?.detected && (
        <div className="p-4 rounded-xl border border-amber-500/40 bg-amber-500/10 text-amber-300 text-sm">
          {T.model_drift_warning.replace('{psi}', Number(drift.psi || 0).toFixed(3))}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="glass-card p-5 space-y-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-blue-500/10 border border-blue-500/30 rounded-xl text-blue-400">
              <BrainCircuit className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-slate-100">{T.model_stage1_title}</h3>
              <p className="text-xs text-slate-400">{T.model_stage1_subtitle}</p>
            </div>
          </div>

          <div className="space-y-2 text-xs border-t border-slate-800 pt-3">
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">{T.model_objective}</span>
              <span className="font-mono text-slate-200">{T.model_binary}</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">{T.model_input_features}</span>
              <span className="font-mono text-blue-400 font-bold">{T.model_features_28}</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">{T.model_val_accuracy}</span>
              <span className="font-mono text-emerald-400 font-bold">{(modelInfo.anomaly_model?.accuracy * 100).toFixed(1)}%</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-slate-400">{T.model_f1_score}</span>
              <span className="font-mono text-emerald-400 font-bold">{(modelInfo.anomaly_model?.f1_score * 100).toFixed(1)}%</span>
            </div>
          </div>
        </div>

        <div className="glass-card p-5 space-y-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-purple-500/10 border border-purple-500/30 rounded-xl text-purple-400">
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-slate-100">{T.model_stage2_title}</h3>
              <p className="text-xs text-slate-400">{T.model_stage2_subtitle}</p>
            </div>
          </div>

          <div className="space-y-2 text-xs border-t border-slate-800 pt-3">
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">{T.model_objective}</span>
              <span className="font-mono text-slate-200">{T.model_multiclass}</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">{T.model_multiclass_acc}</span>
              <span className="font-mono text-emerald-400 font-bold">{(modelInfo.classifier_model?.accuracy * 100).toFixed(1)}%</span>
            </div>
            <div className="py-1">
              <span className="text-slate-400 block mb-1.5">{T.model_classes}</span>
              <div className="flex flex-wrap gap-1">
                {modelInfo.classifier_model?.classes?.map((cls) => (
                  <span key={cls} className="px-2 py-0.5 bg-slate-800 text-slate-300 rounded font-mono text-[10px]">
                    {cls}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ModelInfo;
