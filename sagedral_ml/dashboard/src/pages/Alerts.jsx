import React, { useEffect, useState } from 'react';
import { getAlerts, blockIP } from '../api/client';
import { SeverityBadge } from '../components/SeverityBadge';
import { AlertDetailModal } from '../components/AlertDetailModal';
import { Eye, Download, Search, RefreshCw } from 'lucide-react';
import toast from 'react-hot-toast';

export function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [severity, setSeverity] = useState('');
  const [attackType, setAttackType] = useState('');
  const [srcIp, setSrcIp] = useState('');
  const [loading, setLoading] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState(null);

  const fetchAlerts = async () => {
    setLoading(true);
    try {
      const res = await getAlerts({
        page,
        limit: 25,
        severity: severity || undefined,
        attack_type: attackType || undefined,
        src_ip: srcIp || undefined,
      });
      setAlerts(res.data || []);
      setTotal(res.total || 0);
    } catch (e) {
      toast.error('Failed to fetch alerts list');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [page, severity, attackType]);

  const handleManualBlock = async (ip) => {
    try {
      await blockIP({ ip, reason: 'Manual block from alerts page' });
      toast.success(`IP ${ip} blocked`);
      setSelectedAlert(null);
      fetchAlerts();
    } catch (e) {
      toast.error(e.response?.data?.detail || 'Failed to block IP');
    }
  };

  const exportCSV = () => {
    if (!alerts.length) return;
    const headers = ['Timestamp', 'Source IP', 'Target IP', 'Attack Type', 'Severity', 'Score', 'Action'];
    const rows = alerts.map(a => [
      new Date(a.timestamp * 1000).toISOString(),
      a.src_ip,
      a.dst_ip,
      a.attack_type,
      a.severity,
      a.final_score,
      a.action_taken,
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `sagedral_alerts_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Security Alerts</h1>
          <p className="text-xs text-slate-400 mt-1">Audit log of all detected intrusion threats and anomalies</p>
        </div>
        <button
          onClick={exportCSV}
          className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors"
        >
          <Download className="w-4 h-4" />
          Export CSV
        </button>
      </div>

      {/* Filters Bar */}
      <div className="glass-card p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-3">
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>

          <input
            type="text"
            placeholder="Search by IP..."
            value={srcIp}
            onChange={(e) => setSrcIp(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && fetchAlerts()}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 w-48"
          />

          <button
            onClick={fetchAlerts}
            className="p-2 bg-blue-600/20 text-blue-400 hover:bg-blue-600/30 rounded-lg border border-blue-500/30 transition-colors"
          >
            <Search className="w-4 h-4" />
          </button>
        </div>

        <button
          onClick={fetchAlerts}
          className="p-2 text-slate-400 hover:text-slate-200 transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Alerts Table */}
      <div className="glass-card p-5">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
              <tr>
                <th className="p-3">Time</th>
                <th className="p-3">Source IP</th>
                <th className="p-3">Target IP</th>
                <th className="p-3">Attack Category</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Score</th>
                <th className="p-3">Action</th>
                <th className="p-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {alerts.length > 0 ? (
                alerts.map((a, idx) => (
                  <tr key={a.alert_id || idx} className="hover:bg-slate-800/40 transition-colors">
                    <td className="p-3 font-mono text-slate-400">{new Date(a.timestamp * 1000).toLocaleString()}</td>
                    <td className="p-3 font-mono text-blue-400 font-medium">{a.src_ip}</td>
                    <td className="p-3 font-mono">{a.dst_ip}</td>
                    <td className="p-3 font-semibold">{a.attack_type}</td>
                    <td className="p-3"><SeverityBadge severity={a.severity} /></td>
                    <td className="p-3 font-mono font-bold">{(a.final_score * 100).toFixed(0)}%</td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                        a.action_taken === 'BLOCKED' ? 'bg-red-500/20 text-red-400' : 'bg-amber-500/20 text-amber-400'
                      }`}>
                        {a.action_taken}
                      </span>
                    </td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => setSelectedAlert(a)}
                        className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="8" className="p-6 text-center text-slate-500">No alerts found matching filter criteria.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="mt-4 flex items-center justify-between text-xs text-slate-400 border-t border-slate-800 pt-3">
          <span>Showing Page {page} of {Math.ceil(total / 25) || 1} ({total} total alerts)</span>
          <div className="flex gap-2">
            <button
              disabled={page <= 1}
              onClick={() => setPage(p => p - 1)}
              className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-50 transition-colors"
            >
              Previous
            </button>
            <button
              disabled={page * 25 >= total}
              onClick={() => setPage(p => p + 1)}
              className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-50 transition-colors"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      <AlertDetailModal
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onBlock={handleManualBlock}
      />
    </div>
  );
}
