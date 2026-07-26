import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { ShieldAlert, Eye, EyeOff, Lock, User } from 'lucide-react';
import axios from 'axios';
import toast from 'react-hot-toast';
import { useTranslation } from '../i18n/hook';

export function Login() {
  const { t, T } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();
  const from = location.state?.from?.pathname || '/';

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPwd, setShowPwd] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username || !password) return;

    setLoading(true);
    try {
      const form = new URLSearchParams();
      form.set('username', username);
      form.set('password', password);
      const res = await axios.post('/api/v1/auth/login', form, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      });
      const token = res.data?.token || res.data?.access_token;
      if (token) {
        localStorage.setItem('sagedral_token', token);
        localStorage.setItem('sagedral_user', JSON.stringify(res.data?.user || {}));
        toast.success(T.login_success);
        navigate(from, { replace: true });
      } else {
        toast.error(T.login_failed);
      }
    } catch (err) {
      toast.error(err.response?.data?.detail || T.login_failed);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4 relative overflow-hidden">
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 -left-40 w-80 h-80 bg-blue-600/10 rounded-full blur-3xl" />
        <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-red-600/10 rounded-full blur-3xl" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-purple-600/5 rounded-full blur-3xl" />
      </div>

      <div className="relative z-10 w-full max-w-md">
        <div className="glass-card p-8 space-y-6">
          <div className="flex flex-col items-center text-center space-y-3">
            <div className="p-3.5 bg-blue-600/20 border border-blue-500/40 rounded-2xl text-blue-400">
              <ShieldAlert className="w-8 h-8" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-100 tracking-tight">SAGEDRAL-ML</h1>
              <p className="text-[11px] text-blue-400 font-mono">NIDPS v1.0.0</p>
            </div>
            <div className="pt-2 space-y-1">
              <h2 className="text-lg font-bold text-slate-100">{T.login_title}</h2>
              <p className="text-xs text-slate-400">{T.login_subtitle}</p>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-slate-400">
                {T.username_label}
              </label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder={T.username_placeholder}
                  required
                  autoComplete="username"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-3 py-2.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-colors"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-slate-400">
                {T.password_label}
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                <input
                  type={showPwd ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={T.password_placeholder}
                  required
                  autoComplete="current-password"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-10 py-2.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-colors"
                />
                <button
                  type="button"
                  onClick={() => setShowPwd(v => !v)}
                  tabIndex={-1}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 p-1 text-slate-500 hover:text-slate-300 transition-colors"
                >
                  {showPwd ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading || !username || !password}
              className="w-full py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <svg className="animate-spin w-4 h-4" viewBox="0 0 24 24" fill="none">
                    <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" className="opacity-25" />
                    <path fill="currentColor" className="opacity-75" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  {T.login_loading}
                </>
              ) : (
                T.login_button
              )}
            </button>
          </form>
        </div>

        <p className="text-center text-[11px] text-slate-600 mt-4 font-mono">
          SAGEDRAL-ML Guarda Adaptativu Intelijente
        </p>
      </div>
    </div>
  );
}

export default Login;
