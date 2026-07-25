import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { 
  ShieldAlert, 
  LayoutDashboard, 
  AlertTriangle, 
  Ban, 
  Activity, 
  Settings, 
  BrainCircuit,
  LogOut
} from 'lucide-react';
import { useTranslation } from '../i18n/hook';
import toast from 'react-hot-toast';

export function Sidebar() {
  const { T } = useTranslation();
  const navigate = useNavigate();

  const navItems = [
    { to: '/', label: T.menu_overview, icon: LayoutDashboard },
    { to: '/alerts', label: T.menu_alerts, icon: AlertTriangle },
    { to: '/blocked-ips', label: T.menu_blocked_ips, icon: Ban },
    { to: '/traffic', label: T.menu_traffic, icon: Activity },
    { to: '/settings', label: T.menu_settings, icon: Settings },
    { to: '/model', label: T.menu_model_info, icon: BrainCircuit },
  ];

  const handleLogout = () => {
    localStorage.removeItem('sagedral_token');
    toast.success('Sessão terminada');
    navigate('/login', { replace: true });
  };

  return (
    <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col h-screen sticky top-0">
      <div className="p-5 border-b border-slate-800 flex items-center gap-3">
        <div className="p-2 bg-blue-600/20 border border-blue-500/40 rounded-xl text-blue-400">
          <ShieldAlert className="w-6 h-6" />
        </div>
        <div>
          <h1 className="font-bold text-slate-100 tracking-tight leading-none">{T.app_brand}</h1>
          <span className="text-[10px] text-blue-400 font-mono">{T.app_version}</span>
        </div>
      </div>

      <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-blue-600/10 text-blue-400 border border-blue-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`
              }
            >
              <Icon className="w-4 h-4" />
              {item.label}
            </NavLink>
          );
        })}
      </nav>

      <div className="p-4 border-t border-slate-800 space-y-3">
        <div className="text-xs text-slate-500">
          <p>{T.app_tagline_1}</p>
          <p className="text-[10px] text-slate-600 mt-0.5">{T.app_tagline_2}</p>
        </div>
        <button
          onClick={handleLogout}
          className="w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium text-slate-400 hover:text-red-400 hover:bg-red-500/10 hover:border hover:border-red-500/30 transition-colors"
        >
          <LogOut className="w-4 h-4" />
          {T.menu_logout}
        </button>
      </div>
    </aside>
  );
}

export default Sidebar;
