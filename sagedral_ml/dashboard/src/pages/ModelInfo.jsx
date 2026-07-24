import React, { useEffect, useState } from 'react';
import { getModelInfo } from '../api/client';
import { BrainCircuit, CheckCircle2, Cpu } from 'lucide-react';

export function ModelInfo() {
  const [modelInfo, setModelInfo] = useState(null);

  useEffect(() => {
    getModelInfo().then(setModelInfo).catch(console.error);
  }, []);

  if (!modelInfo) {
    return <div className="text-slate-400 text-xs p-6">Loading model details...</div>;
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-100">Machine Learning Model Architecture</h1>
        <p className="text-xs text-slate-400 mt-1">LightGBM Two-Stage Anomaly Detection & Attack Classification engine</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Stage 1 Card */}
        <div className="glass-card p-5 space-y-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-blue-500/10 border border-blue-500/30 rounded-xl text-blue-400">
              <BrainCircuit className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-slate-100">Stage 1: Anomaly Detector</h3>
              <p className="text-xs text-slate-400">Binary LightGBM Classifier</p>
            </div>
          </div>

          <div className="space-y-2 text-xs border-t border-slate-800 pt-3">
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">Model Objective</span>
              <span className="font-mono text-slate-200">binary (Normal vs Anomaly)</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">Input Feature Count</span>
              <span className="font-mono text-blue-400 font-bold">28 Statistical Features</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">Validation Accuracy</span>
              <span className="font-mono text-emerald-400 font-bold">{(modelInfo.anomaly_model?.accuracy * 100).toFixed(1)}%</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-slate-400">F1 Score</span>
              <span className="font-mono text-emerald-400 font-bold">{(modelInfo.anomaly_model?.f1_score * 100).toFixed(1)}%</span>
            </div>
          </div>
        </div>

        {/* Stage 2 Card */}
        <div className="glass-card p-5 space-y-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-purple-500/10 border border-purple-500/30 rounded-xl text-purple-400">
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-slate-100">Stage 2: Attack Classifier</h3>
              <p className="text-xs text-slate-400">Multiclass LightGBM Classifier</p>
            </div>
          </div>

          <div className="space-y-2 text-xs border-t border-slate-800 pt-3">
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">Model Objective</span>
              <span className="font-mono text-slate-200">multiclass</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="text-slate-400">Multiclass Accuracy</span>
              <span className="font-mono text-emerald-400 font-bold">{(modelInfo.classifier_model?.accuracy * 100).toFixed(1)}%</span>
            </div>
            <div className="py-1">
              <span className="text-slate-400 block mb-1.5">Supported Attack Classes:</span>
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
