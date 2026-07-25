import React, { useEffect, useState } from 'react';
import { getBlockedIPs, blockIP, unblockIP } from '../api/client';
import { ConfirmDialog } from '../components/ConfirmDialog';
import { useTranslation } from '../i18n/hook';
import { Ban, ShieldCheck, Plus, Trash2 } from 'lucide-react';
import toast from 'react-hot-toast';

export function BlockedIPs() {
  const { t, T } = useTranslation();
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [ipInput, setIpInput] = useState('');
  const [reasonInput, setReasonInput] = useState('');
  const [durationInput, setDurationInput] = useState(3600);
  const [loading, setLoading] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [pendingUnblockIp, setPendingUnblockIp] = useState(null);

  const fetchBlocked = async () => {
    try {
      const res = await getBlockedIPs();
      setBlockedIPs(res.data || []);
    } catch (e) {
      toast.error(T.blocked_fetch_fail);
    }
  };

  useEffect(() => {
    fetchBlocked();
  }, []);

  const handleManualBlock = async (e) => {
    e.preventDefault();
    if (!ipInput) return;
    setConfirmOpen(true);
  };

  const confirmBlock = async () => {
    setConfirmOpen(false);
    if (!ipInput) return;

    setLoading(true);
    try {
      await blockIP({
        ip: ipInput,
        reason: reasonInput || 'Manual block via dashboard',
        duration_seconds: parseInt(durationInput),
      });
      toast.success(t('blocked_success', { ip: ipInput }));
      setIpInput('');
      setReasonInput('');
      fetchBlocked();
    } catch (err) {
      toast.error(err.response?.data?.detail || T.blocked_fail);
    } finally {
      setLoading(false);
    }
  };

  const requestUnblock = (ip) => {
    setPendingUnblockIp(ip);
  };

  const confirmUnblock = async () => {
    if (!pendingUnblockIp) return;
    const ip = pendingUnblockIp;
    setPendingUnblockIp(null);
    try {
      await unblockIP(ip);
      toast.success(t('unblock_success', { ip }));
      fetchBlocked();
    } catch (err) {
      toast.error(err.response?.data?.detail || T.unblock_fail);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-100">{T.blocked_title}</h1>
        <p className="text-xs text-slate-400 mt-1">{T.blocked_subtitle}</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="glass-card p-5 h-fit">
          <div className="flex items-center gap-2 mb-4 text-slate-200">
            <Plus className="w-4 h-4 text-red-400" />
            <h3 className="text-sm font-semibold">{T.blocked_manual_title}</h3>
          </div>

          <form onSubmit={handleManualBlock} className="space-y-4 text-xs">
            <div>
              <label className="block text-slate-400 mb-1 font-medium">{T.blocked_ip_label}</label>
              <input
                type="text"
                placeholder={T.blocked_ip_placeholder}
                value={ipInput}
                onChange={(e) => setIpInput(e.target.value)}
                required
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-red-500 font-mono"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1 font-medium">{T.blocked_reason_label}</label>
              <input
                type="text"
                placeholder={T.blocked_reason_placeholder}
                value={reasonInput}
                onChange={(e) => setReasonInput(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-red-500"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1 font-medium">{T.blocked_duration_label}</label>
              <select
                value={durationInput}
                onChange={(e) => setDurationInput(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-red-500"
              >
                <option value={900}>{T.blocked_duration_15min}</option>
                <option value={3600}>{T.blocked_duration_1h}</option>
                <option value={86400}>{T.blocked_duration_24h}</option>
                <option value={0}>{T.blocked_duration_perm}</option>
              </select>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-lg bg-red-600 hover:bg-red-700 text-white font-semibold flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
            >
              <Ban className="w-4 h-4" />
              {T.blocked_enforce_btn}
            </button>
          </form>
        </div>

        <div className="glass-card p-5 lg:col-span-2">
          <h3 className="text-sm font-semibold text-slate-200 mb-4">{T.blocked_list_title}</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                <tr>
                  <th className="p-3">{T.col_ip_address}</th>
                  <th className="p-3">{T.col_blocked_time}</th>
                  <th className="p-3">{T.col_reason}</th>
                  <th className="p-3">{T.col_source}</th>
                  <th className="p-3 text-right">{T.col_action}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {blockedIPs.length > 0 ? (
                  blockedIPs.map((item) => (
                    <tr key={item.ip} className="hover:bg-slate-800/40 transition-colors">
                      <td className="p-3 font-mono text-red-400 font-semibold">{item.ip}</td>
                      <td className="p-3 font-mono text-slate-400">{new Date(item.blocked_at * 1000).toLocaleString()}</td>
                      <td className="p-3">{item.reason || T.modal_na}</td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                          item.blocked_by === 'manual' ? 'bg-amber-500/20 text-amber-400' : 'bg-blue-500/20 text-blue-400'
                        }`}>
                          {item.blocked_by}
                        </span>
                      </td>
                      <td className="p-3 text-right">
                        <button
                          onClick={() => requestUnblock(item.ip)}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-emerald-600/20 text-slate-300 hover:text-emerald-400 border border-slate-700 transition-colors flex items-center gap-1 ml-auto"
                        >
                          <ShieldCheck className="w-3.5 h-3.5" />
                          {T.blocked_unblock_btn}
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="5" className="p-6 text-center text-slate-500">{T.no_blocked_ips}</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <ConfirmDialog
        isOpen={confirmOpen}
        title={T.confirm_block_title}
        body={t('confirm_block_body', { ip: ipInput })}
        confirmLabel={T.confirm_block_yes}
        onConfirm={confirmBlock}
        onCancel={() => setConfirmOpen(false)}
        danger={true}
      />

      <ConfirmDialog
        isOpen={!!pendingUnblockIp}
        title={T.confirm_unblock_title}
        body={t('confirm_unblock_body', { ip: pendingUnblockIp || '' })}
        confirmLabel={T.confirm_unblock_yes}
        onConfirm={confirmUnblock}
        onCancel={() => setPendingUnblockIp(null)}
        danger={false}
      />
    </div>
  );
}

export default BlockedIPs;
