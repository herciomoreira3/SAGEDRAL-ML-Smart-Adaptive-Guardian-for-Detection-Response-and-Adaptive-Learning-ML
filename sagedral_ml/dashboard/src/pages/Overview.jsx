import React, { useEffect, useState } from 'react';
import { StatsCard } from '../components/StatsCard';
import { SeverityBadge } from '../components/SeverityBadge';
import { AlertDetailModal } from '../components/AlertDetailModal';
import { ConfirmDialog } from '../components/ConfirmDialog';
import { getStatus, getAlerts, getBlockedIPs, getTrafficStats, getCaptureStats, blockIP } from '../api/client';
import { useWebSocket } from '../hooks/useWebSocket';
import { useTranslation } from '../i18n/hook';
import { 
  ShieldAlert, 
  AlertTriangle, 
  Ban, 
  Activity, 
  Eye 
} from 'lucide-react';
import { 
  ResponsiveContainer, 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  Tooltip, 
  PieChart, 
  Pie, 
  Cell 
} from 'recharts';
import toast from 'react-hot-toast';

const COLORS = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#8b5cf6', '#ec4899'];

export function Overview() {
  const { t, T } = useTranslation();
  const { lastAlert, trafficStats: wsTraffic } = useWebSocket();
  const [status, setStatus] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [blockedCount, setBlockedCount] = useState(0);
  const [chartData, setChartData] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [pendingBlockIp, setPendingBlockIp] = useState(null);
  const [captureStats, setCaptureStats] = useState(null);

  const fetchData = async () => {
    try {
      const s = await getStatus();
      setStatus(s);

      const a = await getAlerts({ limit: 10 });
      setAlerts(a.data || []);

      const b = await getBlockedIPs();
      setBlockedCount(b.total || 0);

      const t = await getTrafficStats({ limit: 30 });
      setChartData(t.data || []);

      try {
        const cap = await getCaptureStats();
        setCaptureStats(cap);
      } catch {
        setCaptureStats(null);
      }
    } catch (e) {
      console.error('Failed to fetch overview data', e);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (lastAlert) {
      setAlerts(prev => [lastAlert, ...prev.slice(0, 9)]);
      toast.error(t('block_alert_success', {
        severity: lastAlert.severity,
        attack: lastAlert.attack_type,
        ip: lastAlert.src_ip,
      }));
    }
  }, [lastAlert, t]);

  useEffect(() => {
    if (wsTraffic) {
      setChartData(prev => [...prev.slice(1), wsTraffic]);
    }
  }, [wsTraffic]);

  const requestBlock = (ip) => {
    setPendingBlockIp(ip);
  };

  const confirmBlock = async () => {
    if (!pendingBlockIp) return;
    const ip = pendingBlockIp;
    setPendingBlockIp(null);
    try {
      await blockIP({ ip, reason: 'Manual block from dashboard overview' });
      toast.success(t('blocked_success', { ip }));
      setSelectedAlert(null);
      fetchData();
    } catch (e) {
      toast.error(e.response?.data?.detail || T.blocked_fail);
    }
  };

  const attackTypeCounts = alerts.reduce((acc, curr) => {
    acc[curr.attack_type] = (acc[curr.attack_type] || 0) + 1;
    return acc;
  }, {});

  const pieData = Object.keys(attackTypeCounts).map(type => ({
    name: type,
    value: attackTypeCounts[type],
  }));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">{T.overview_title}</h1>
          <p className="text-xs text-slate-400 mt-1">{T.overview_subtitle}</p>
        </div>
        <div className="text-xs text-slate-400 font-mono">
          {T.overview_interface}: <span className="text-blue-400 font-semibold">{status?.interface || 'eth0'}</span> | {T.overview_uptime}: {status?.uptime_seconds || 0}s
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <StatsCard
          title={T.stat_system_status}
          value={status?.status === 'running' ? T.stat_active_guard : T.stat_inactive}
          icon={ShieldAlert}
          color={status?.status === 'running' ? 'emerald' : 'red'}
          trend={T.stat_protection_live}
        />
        <StatsCard
          title={T.stat_recent_alerts}
          value={alerts.length}
          icon={AlertTriangle}
          color="amber"
          trend={T.stat_last_24h}
        />
        <StatsCard
          title={T.stat_blocked_ips}
          value={blockedCount}
          icon={Ban}
          color="red"
          trend={T.stat_enforced_kernel}
        />
        <StatsCard
          title={T.stat_ml_engine}
          value={status?.ml_model_loaded ? T.stat_ml_active : T.stat_ml_fallback}
          icon={Activity}
          color="blue"
          trend={T.stat_ml_type}
        />
        <StatsCard
          title={T.stat_capture_drop}
          value={
            captureStats?.status === 'unavailable'
              ? T.stat_capture_inactive
              : `${(captureStats?.drop_rate_pct ?? 0).toFixed(1)}%`
          }
          icon={Activity}
          color={
            captureStats?.drop_rate_pct > 1 ? 'red' : 'emerald'
          }
          trend={
            captureStats?.drop_rate_pct > 1
              ? T.stat_capture_drop_warn
              : (captureStats?.is_running ? T.stat_capture_active : T.stat_capture_inactive)
          }
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="glass-card p-5 lg:col-span-2 flex flex-col">
          <h3 className="text-sm font-semibold text-slate-200 mb-4">{T.traffic_chart}</h3>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="packetsGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="timestamp" tickFormatter={(t) => new Date(t * 1000).toLocaleTimeString()} stroke="#64748b" fontSize={10} />
                <YAxis stroke="#64748b" fontSize={10} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '0.5rem', fontSize: '12px' }}
                />
                <Area type="monotone" dataKey="packets_per_sec" stroke="#3b82f6" fillOpacity={1} fill="url(#packetsGradient)" name={T.traffic_packets_per_sec} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="glass-card p-5 flex flex-col">
          <h3 className="text-sm font-semibold text-slate-200 mb-4">{T.alerts_by_category}</h3>
          {pieData.length > 0 ? (
            <div className="h-64 w-full flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={75} label>
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '0.5rem', fontSize: '12px' }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-xs text-slate-500">
              {T.alerts_no_threats}
            </div>
          )}
        </div>
      </div>

      <div className="glass-card p-5">
        <h3 className="text-sm font-semibold text-slate-200 mb-4">{T.recent_threats}</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
              <tr>
                <th className="p-3">{T.col_time}</th>
                <th className="p-3">{T.col_src_ip}</th>
                <th className="p-3">{T.col_dst_ip}</th>
                <th className="p-3">{T.col_attack}</th>
                <th className="p-3">{T.col_severity}</th>
                <th className="p-3">{T.col_score}</th>
                <th className="p-3">{T.col_action}</th>
                <th className="p-3 text-right">{T.col_details}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {alerts.length > 0 ? (
                alerts.map((a, idx) => (
                  <tr key={a.alert_id || idx} className="hover:bg-slate-800/40 transition-colors">
                    <td className="p-3 font-mono text-slate-400">{new Date(a.timestamp * 1000).toLocaleTimeString()}</td>
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
                  <td colSpan="8" className="p-6 text-center text-slate-500">{T.no_alerts}</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <AlertDetailModal 
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onBlock={requestBlock}
      />

      <ConfirmDialog
        isOpen={!!pendingBlockIp}
        title={T.confirm_block_title}
        body={t('confirm_block_body', { ip: pendingBlockIp || '' })}
        confirmLabel={T.confirm_block_yes}
        onConfirm={confirmBlock}
        onCancel={() => setPendingBlockIp(null)}
        danger={true}
      />
    </div>
  );
}

export default Overview;
