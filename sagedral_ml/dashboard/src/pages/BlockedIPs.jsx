import React, { useEffect, useState } from 'react';
import { getBlockedIPs, blockIP, unblockIP } from '../api/client';
import { Ban, ShieldCheck, Plus, Trash2 } from 'lucide-react';
import toast from 'react-hot-toast';

export function BlockedIPs() {
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [ipInput, setIpInput] = useState('');
  const [reasonInput, setReasonInput] = useState('');
  const [durationInput, setDurationInput] = useState(3600);
  const [loading, setLoading] = useState(false);

  const fetchBlocked = async () => {
    try {
      const res = await getBlockedIPs();
      setBlockedIPs(res.data || []);
    } catch (e) {
      toast.error('Failed to fetch blocked IP list');
    }
  };

  useEffect(() => {
    fetchBlocked();
  }, []);

  const handleManualBlock = async (e) => {
    e.preventDefault();
    if (!ipInput) return;

    setLoading(true);
    try {
      await blockIP({
        ip: ipInput,
        reason: reasonInput || 'Manual block via dashboard',
        duration_seconds: parseInt(durationInput),
      });
      toast.success(`IP ${ipInput} blocked successfully`);
      setIpInput('');
      setReasonInput('');
      fetchBlocked();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Failed to block IP');
    } finally {
      setLoading(false);
    }
  };

  const handleUnblock = async (ip) => {
    try {
      await unblockIP(ip);
      toast.success(`IP ${ip} unblocked successfully`);
      fetchBlocked();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Failed to unblock IP');
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-100">Active IPS Blocked IPs</h1>
        <p className="text-xs text-slate-400 mt-1">IP address firewall blocklist enforced at kernel level (nftables/iptables)</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Manual Block Form */}
        <div className="glass-card p-5 h-fit">
          <div className="flex items-center gap-2 mb-4 text-slate-200">
            <Plus className="w-4 h-4 text-red-400" />
            <h3 className="text-sm font-semibold">Manual IP Block</h3>
          </div>

          <form onSubmit={handleManualBlock} className="space-y-4 text-xs">
            <div>
              <label className="block text-slate-400 mb-1 font-medium">IP Address</label>
              <input
                type="text"
                placeholder="e.g. 192.168.1.100"
                value={ipInput}
                onChange={(e) => setIpInput(e.target.value)}
                required
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-red-500 font-mono"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1 font-medium">Reason</label>
              <input
                type="text"
                placeholder="Suspicious probe / port scan"
                value={reasonInput}
                onChange={(e) => setReasonInput(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-red-500"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1 font-medium">Duration</label>
              <select
                value={durationInput}
                onChange={(e) => setDurationInput(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-red-500"
              >
                <option value={900}>15 Minutes</option>
                <option value={3600}>1 Hour</option>
                <option value={86400}>24 Hours</option>
                <option value={0}>Permanent (No auto-unblock)</option>
              </select>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-lg bg-red-600 hover:bg-red-700 text-white font-semibold flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
            >
              <Ban className="w-4 h-4" />
              Enforce Block
            </button>
          </form>
        </div>

        {/* Blocked Table */}
        <div className="glass-card p-5 lg:col-span-2">
          <h3 className="text-sm font-semibold text-slate-200 mb-4">Active Blocked IP List</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                <tr>
                  <th className="p-3">IP Address</th>
                  <th className="p-3">Blocked Time</th>
                  <th className="p-3">Reason</th>
                  <th className="p-3">Source</th>
                  <th className="p-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {blockedIPs.length > 0 ? (
                  blockedIPs.map((item) => (
                    <tr key={item.ip} className="hover:bg-slate-800/40 transition-colors">
                      <td className="p-3 font-mono text-red-400 font-semibold">{item.ip}</td>
                      <td className="p-3 font-mono text-slate-400">{new Date(item.blocked_at * 1000).toLocaleString()}</td>
                      <td className="p-3">{item.reason || 'N/A'}</td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                          item.blocked_by === 'manual' ? 'bg-amber-500/20 text-amber-400' : 'bg-blue-500/20 text-blue-400'
                        }`}>
                          {item.blocked_by}
                        </span>
                      </td>
                      <td className="p-3 text-right">
                        <button
                          onClick={() => handleUnblock(item.ip)}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-emerald-600/20 text-slate-300 hover:text-emerald-400 border border-slate-700 transition-colors flex items-center gap-1 ml-auto"
                        >
                          <ShieldCheck className="w-3.5 h-3.5" />
                          Unblock
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="5" className="p-6 text-center text-slate-500">No active IP block rules in firewall.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
