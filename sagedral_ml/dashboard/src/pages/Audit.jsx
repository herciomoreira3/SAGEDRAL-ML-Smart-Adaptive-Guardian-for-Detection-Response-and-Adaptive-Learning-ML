import React, { useEffect, useState } from 'react';
import { RefreshCw, ScrollText } from 'lucide-react';
import toast from 'react-hot-toast';
import { getAuditLogs } from '../api/client';
import { useTranslation } from '../i18n/hook';

export function Audit() {
  const { T } = useTranslation();
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const response = await getAuditLogs({ limit: 200 });
      setRows(response.data || []);
    } catch {
      toast.error(T.audit_fetch_fail);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
            <ScrollText className="w-6 h-6 text-blue-400" />
            {T.audit_title}
          </h1>
          <p className="text-xs text-slate-400 mt-1">{T.audit_subtitle}</p>
        </div>
        <button onClick={load} className="p-2 rounded-lg bg-slate-800 text-slate-300">
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>
      <div className="glass-card overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-950/60 text-slate-400 uppercase">
            <tr>
              <th className="p-3">{T.col_time}</th>
              <th className="p-3">{T.audit_user}</th>
              <th className="p-3">{T.audit_event}</th>
              <th className="p-3">{T.audit_target}</th>
              <th className="p-3">{T.audit_ip}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {rows.length ? rows.map((row) => (
              <tr key={row.id} className="text-slate-300">
                <td className="p-3 font-mono">{new Date(row.timestamp * 1000).toLocaleString()}</td>
                <td className="p-3">{row.username || 'sistema'}</td>
                <td className="p-3 font-semibold text-blue-400">{row.action_type}</td>
                <td className="p-3 font-mono">{row.target_entity || '—'}:{row.target_id || '—'}</td>
                <td className="p-3 font-mono">{row.ip_address || '—'}</td>
              </tr>
            )) : (
              <tr><td colSpan="5" className="p-6 text-center text-slate-500">{T.audit_empty}</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default Audit;
