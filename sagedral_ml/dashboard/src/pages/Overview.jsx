import React, { useEffect, useState } from 'react';
import { StatsCard } from '../components/StatsCard';
import { SeverityBadge } from '../components/SeverityBadge';
import { AlertDetailModal } from '../components/AlertDetailModal';
import { getStatus, getAlerts, getBlockedIPs, getTrafficStats, blockIP } from '../api/client';
import { useWebSocket } from '../hooks/useWebSocket';
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
  const { lastAlert, trafficStats: wsTraffic } = useWebSocket();
  const [status, setStatus] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [blockedCount, setBlockedCount] = useState(0);
  const [chartData, setChartData] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);

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
      toast.error(`New ${lastAlert.severity} alert: ${lastAlert.attack_type} from ${lastAlert.src_ip}`);
    }
  }, [lastAlert]);

  useEffect(() => {
    if (wsTraffic) {
      setChartData(prev => [...prev.slice(1), wsTraffic]);
    }
  }, [wsTraffic]);

  const handleManualBlock = async (ip) => {
    try {
      await blockIP({ ip, reason: 'Manual block from dashboard overview' });
      toast.success(`IP ${ip} blocked successfully`);
      setSelectedAlert(null);
      fetchData();
    } catch (e) {
      toast.error(e.response?.data?.detail || 'Failed to block IP');
    }
  };

  // Distribution chart data
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
      {/* Header Banner */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">System Overview</h1>
          <p className="text-xs text-slate-400 mt-1">Real-time Network Intrusion Detection & Response Summary</p>
        </div>
        <div className="text-xs text-slate-400 font-mono">
          Interface: <span className="text-blue-400 font-semibold">{status?.interface || 'eth0'}</span> | Uptime: {status?.uptime_seconds || 0}s
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatsCard
          title="System Status"
          value={status?.status === 'running' ? 'Active Guard' : 'Inactive'}
          icon={ShieldAlert}
          color={status?.status === 'running' ? 'emerald' : 'red'}
          trend="NIDPS Protection Live"
        />
        <StatsCard
          title="Total Recent Alerts"
          value={alerts.length}
          icon={AlertTriangle}
          color="amber"
          trend="Last 24 hours"
        />
        <StatsCard
          title="Active Blocked IPs"
          value={blockedCount}
          icon={Ban}
          color="red"
          trend="Enforced in Kernel"
        />
        <StatsCard
          title="ML Engine Status"
          value={status?.ml_model_loaded ? 'LightGBM Active' : 'Fallback Mode'}
          icon={Activity}
          color="blue"
          trend="Anomaly + Classifier"
        />
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Real-time Throughput Chart */}
        <div className="glass-card p-5 lg:col-span-2 flex flex-col">
          <h3 className="text-sm font-semibold text-slate-200 mb-4">Real-time Traffic Throughput</h3>
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
                <Area type="monotone" dataKey="packets_per_sec" stroke="#3b82f6" fillOpacity={1} fill="url(#packetsGradient)" name="Packets / Sec" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Attack Type Pie Chart */}
        <div className="glass-card p-5 flex flex-col">
          <h3 className="text-sm font-semibold text-slate-200 mb-4">Alerts by Attack Category</h3>
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
              No threat alerts recorded yet
            </div>
          )}
        </div>
      </div>

      {/* Recent Alerts Table */}
      <div className="glass-card p-5">
        <h3 className="text-sm font-semibold text-slate-200 mb-4">Recent Threat Events</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
              <tr>
                <th className="p-3">Time</th>
                <th className="p-3">Source IP</th>
                <th className="p-3">Target IP</th>
                <th className="p-3">Attack Type</th>
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
                  <td colSpan="8" className="p-6 text-center text-slate-500">No security alerts detected. System operating normally.</td>
                </tr>
              )}
            </tbody>
          </table>
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
