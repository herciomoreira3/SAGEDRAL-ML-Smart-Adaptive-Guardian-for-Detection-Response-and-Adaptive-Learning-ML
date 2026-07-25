import React, { useEffect, useState } from 'react';
import { getTrafficStats } from '../api/client';
import { useTranslation } from '../i18n/hook';
import { Activity, RefreshCw } from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';

export function Traffic() {
  const { T } = useTranslation();
  const [stats, setStats] = useState([]);
  const [limit, setLimit] = useState(60);

  const fetchTraffic = async () => {
    try {
      const res = await getTrafficStats({ limit });
      setStats(res.data || []);
    } catch (e) {
      console.error(T.traffic_fetch_fail, e);
    }
  };

  useEffect(() => {
    fetchTraffic();
  }, [limit]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">{T.traffic_title}</h1>
          <p className="text-xs text-slate-400 mt-1">{T.traffic_subtitle}</p>
        </div>
        <button
          onClick={fetchTraffic}
          className="p-2 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      <div className="glass-card p-5">
        <h3 className="text-sm font-semibold text-slate-200 mb-4">{T.traffic_pps_title}</h3>
        <div className="h-80 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={stats}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="timestamp" tickFormatter={(t) => new Date(t * 1000).toLocaleTimeString()} stroke="#64748b" fontSize={11} />
              <YAxis stroke="#64748b" fontSize={11} />
              <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '0.5rem', fontSize: '12px' }} />
              <Area type="monotone" dataKey="packets_per_sec" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.2} name={T.traffic_packets_per_sec} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="glass-card p-5">
        <h3 className="text-sm font-semibold text-slate-200 mb-4">{T.traffic_bps_title}</h3>
        <div className="h-80 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={stats}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="timestamp" tickFormatter={(t) => new Date(t * 1000).toLocaleTimeString()} stroke="#64748b" fontSize={11} />
              <YAxis stroke="#64748b" fontSize={11} />
              <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '0.5rem', fontSize: '12px' }} />
              <Area type="monotone" dataKey="bytes_per_sec" stroke="#10b981" fill="#10b981" fillOpacity={0.2} name={T.traffic_bytes_per_sec} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}

export default Traffic;
