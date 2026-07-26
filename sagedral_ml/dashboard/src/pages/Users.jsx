import React, { useEffect, useState } from 'react';
import { RefreshCw, ShieldCheck, UserPlus } from 'lucide-react';
import toast from 'react-hot-toast';
import {
  createUser,
  deleteUser,
  getUsers,
  updateUser,
} from '../api/client';
import { ConfirmDialog } from '../components/ConfirmDialog';
import { useTranslation } from '../i18n/hook';

const EMPTY_FORM = {
  username: '',
  password: '',
  role: 'viewer',
  full_name: '',
  email: '',
};

export function Users() {
  const { T, t } = useTranslation();
  const [rows, setRows] = useState([]);
  const [form, setForm] = useState(EMPTY_FORM);
  const [loading, setLoading] = useState(false);
  const [pendingDelete, setPendingDelete] = useState(null);

  const load = async () => {
    setLoading(true);
    try {
      const response = await getUsers();
      setRows(response.data || []);
    } catch {
      toast.error(T.users_fetch_fail);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const submit = async (event) => {
    event.preventDefault();
    try {
      await createUser(form);
      setForm(EMPTY_FORM);
      toast.success(T.users_created);
      await load();
    } catch (error) {
      toast.error(error.response?.data?.detail || T.users_change_fail);
    }
  };

  const patch = async (row, values) => {
    try {
      await updateUser(row.id, values);
      toast.success(T.users_updated);
      await load();
    } catch (error) {
      toast.error(error.response?.data?.detail || T.users_change_fail);
    }
  };

  const confirmDelete = async () => {
    const target = pendingDelete;
    setPendingDelete(null);
    if (!target) return;
    try {
      await deleteUser(target.id);
      toast.success(T.users_deleted);
      await load();
    } catch (error) {
      toast.error(error.response?.data?.detail || T.users_change_fail);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
            <ShieldCheck className="w-6 h-6 text-blue-400" />
            {T.users_title}
          </h1>
          <p className="text-xs text-slate-400 mt-1">{T.users_subtitle}</p>
        </div>
        <button onClick={load} className="p-2 rounded-lg bg-slate-800 text-slate-300">
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      <form onSubmit={submit} className="glass-card p-5 grid grid-cols-1 md:grid-cols-6 gap-3 text-xs">
        <div className="md:col-span-6 flex items-center gap-2 text-slate-200 font-semibold">
          <UserPlus className="w-4 h-4 text-blue-400" />
          {T.users_add}
        </div>
        <input
          required
          minLength={3}
          maxLength={50}
          placeholder={T.users_username}
          value={form.username}
          onChange={(event) => setForm({ ...form, username: event.target.value })}
          className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200"
        />
        <input
          required
          type="password"
          minLength={12}
          maxLength={128}
          placeholder={`${T.users_password} (min. 12)`}
          value={form.password}
          onChange={(event) => setForm({ ...form, password: event.target.value })}
          className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200"
        />
        <input
          placeholder={T.users_full_name}
          value={form.full_name}
          onChange={(event) => setForm({ ...form, full_name: event.target.value })}
          className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200"
        />
        <input
          type="email"
          placeholder={T.users_email}
          value={form.email}
          onChange={(event) => setForm({ ...form, email: event.target.value })}
          className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200"
        />
        <select
          value={form.role}
          onChange={(event) => setForm({ ...form, role: event.target.value })}
          className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200"
        >
          <option value="viewer">Viewer</option>
          <option value="analyst">Analyst</option>
          <option value="admin">Admin</option>
        </select>
        <button className="rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold px-3 py-2">
          {T.users_add}
        </button>
      </form>

      <div className="glass-card overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-950/60 text-slate-400 uppercase">
            <tr>
              <th className="p-3">{T.users_username}</th>
              <th className="p-3">{T.users_full_name}</th>
              <th className="p-3">{T.users_role}</th>
              <th className="p-3">{T.users_status}</th>
              <th className="p-3">{T.users_actions}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {rows.map((row) => (
              <tr key={row.id} className="text-slate-300">
                <td className="p-3">
                  <div className="font-semibold">{row.username}</div>
                  <div className="text-slate-500">{row.email || '—'}</div>
                </td>
                <td className="p-3">{row.full_name || '—'}</td>
                <td className="p-3">
                  <select
                    value={row.role}
                    onChange={(event) => patch(row, { role: event.target.value })}
                    className="bg-slate-950 border border-slate-800 rounded px-2 py-1"
                  >
                    <option value="viewer">Viewer</option>
                    <option value="analyst">Analyst</option>
                    <option value="admin">Admin</option>
                  </select>
                </td>
                <td className="p-3">
                  <span className={row.is_active ? 'text-emerald-400' : 'text-red-400'}>
                    {row.is_active ? T.users_active : T.users_disabled}
                  </span>
                </td>
                <td className="p-3 space-x-2">
                  <button
                    onClick={() => patch(row, { is_active: !row.is_active })}
                    className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700"
                  >
                    {row.is_active ? T.users_disable : T.users_enable}
                  </button>
                  <button
                    onClick={() => setPendingDelete(row)}
                    className="px-2 py-1 rounded bg-red-500/10 text-red-400 hover:bg-red-500/20"
                  >
                    {T.users_delete}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <ConfirmDialog
        isOpen={!!pendingDelete}
        title={T.users_confirm_delete_title}
        body={t('users_confirm_delete_body', { username: pendingDelete?.username || '' })}
        confirmLabel={T.users_delete}
        onConfirm={confirmDelete}
        onCancel={() => setPendingDelete(null)}
      />
    </div>
  );
}

export default Users;
