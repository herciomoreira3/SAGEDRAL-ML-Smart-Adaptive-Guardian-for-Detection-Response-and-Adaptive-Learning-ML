import React, { useEffect, useState } from 'react';
import { getConfig, updateConfig } from '../api/client';
import { ConfirmDialog } from '../components/ConfirmDialog';
import { useTranslation } from '../i18n/hook';
import { Settings as SettingsIcon, Save, RefreshCw } from 'lucide-react';
import toast from 'react-hot-toast';

export function Settings() {
  const { T } = useTranslation();
  const [config, setConfigData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);

  const fetchConfig = async () => {
    try {
      const c = await getConfig();
      setConfigData(c);
    } catch (e) {
      toast.error(T.settings_load_fail);
    }
  };

  useEffect(() => {
    fetchConfig();
  }, []);

  const handleSaveClick = (e) => {
    if (e) e.preventDefault();
    setConfirmOpen(true);
  };

  const confirmSave = async () => {
    setConfirmOpen(false);
    setLoading(true);
    try {
      const res = await updateConfig(config);
      toast.success(res.message || T.settings_save_success);
      if (res.requires_restart?.length) {
        toast(T.settings_restart_warn, { icon: '⚠️' });
      }
    } catch (err) {
      toast.error(err.response?.data?.detail?.message || T.settings_save_fail);
    } finally {
      setLoading(false);
    }
  };

  if (!config) {
    return <div className="text-slate-400 text-xs p-6">{T.settings_loading}</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">{T.settings_title}</h1>
          <p className="text-xs text-slate-400 mt-1">{T.settings_subtitle}</p>
        </div>
        <button
          onClick={handleSaveClick}
          disabled={loading}
          className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs transition-colors disabled:opacity-50"
        >
          <Save className="w-4 h-4" />
          {T.settings_save_changes}
        </button>
      </div>

      <form onSubmit={handleSaveClick} className="space-y-6">
        <div className="glass-card p-5 space-y-4">
          <h3 className="text-sm font-semibold text-slate-200 border-b border-slate-800 pb-2">{T.settings_network_title}</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div>
              <label className="block text-slate-400 mb-1 font-medium">{T.settings_capture_iface}</label>
              <input
                type="text"
                value={config.capture?.interface || ''}
                onChange={(e) => setConfigData({
                  ...config,
                  capture: { ...config.capture, interface: e.target.value }
                })}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 font-mono focus:outline-none focus:border-blue-500"
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1 font-medium">{T.settings_bpf_filter}</label>
              <input
                type="text"
                placeholder={T.settings_bpf_placeholder}
                value={config.capture?.bpf_filter || ''}
                onChange={(e) => setConfigData({
                  ...config,
                  capture: { ...config.capture, bpf_filter: e.target.value }
                })}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 font-mono focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>
        </div>

        <div className="glass-card p-5 space-y-4">
          <h3 className="text-sm font-semibold text-slate-200 border-b border-slate-800 pb-2">{T.settings_detection_title}</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
            <div>
              <label className="block text-slate-400 mb-1 font-medium">
                {T.settings_ml_anomaly}: <span className="text-blue-400 font-bold">{config.ml?.anomaly_threshold}</span>
              </label>
              <input
                type="range"
                min="0.1"
                max="0.95"
                step="0.05"
                value={config.ml?.anomaly_threshold || 0.7}
                onChange={(e) => setConfigData({
                  ...config,
                  ml: { ...config.ml, anomaly_threshold: parseFloat(e.target.value) }
                })}
                className="w-full accent-blue-500"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1 font-medium">
                {T.settings_ips_block}: <span className="text-red-400 font-bold">{config.decision?.block_threshold}</span>
              </label>
              <input
                type="range"
                min="0.4"
                max="0.95"
                step="0.05"
                value={config.decision?.block_threshold || 0.7}
                onChange={(e) => setConfigData({
                  ...config,
                  decision: { ...config.decision, block_threshold: parseFloat(e.target.value) }
                })}
                className="w-full accent-red-500"
              />
            </div>
          </div>
        </div>

        <div className="glass-card p-5 space-y-4">
          <h3 className="text-sm font-semibold text-slate-200 border-b border-slate-800 pb-2">{T.settings_ips_title}</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div>
              <label className="block text-slate-400 mb-1 font-medium">{T.settings_backend}</label>
              <select
                value={config.ips?.preferred_backend || 'nftables'}
                onChange={(e) => setConfigData({
                  ...config,
                  ips: { ...config.ips, preferred_backend: e.target.value }
                })}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-blue-500"
              >
                <option value="nftables">{T.settings_backend_nft}</option>
                <option value="iptables">{T.settings_backend_ipt}</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-400 mb-1 font-medium">{T.settings_auto_unblock}</label>
              <input
                type="number"
                value={config.ips?.auto_unblock_after || 3600}
                onChange={(e) => setConfigData({
                  ...config,
                  ips: { ...config.ips, auto_unblock_after: parseInt(e.target.value) }
                })}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 font-mono focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>
        </div>
      </form>

      <ConfirmDialog
        isOpen={confirmOpen}
        title={T.confirm_save_title}
        body={T.confirm_save_body}
        confirmLabel={T.confirm_save_yes}
        onConfirm={confirmSave}
        onCancel={() => setConfirmOpen(false)}
        danger={false}
      />
    </div>
  );
}

export default Settings;
