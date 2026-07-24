import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  ShieldAlert, 
  LayoutDashboard, 
  AlertTriangle, 
  Ban, 
  Activity, 
  Settings, 
  BrainCircuit 
} from 'lucide-react';

export function Sidebar() {
  const navItems = [
    { to: '/', label: 'Overview', icon: LayoutDashboard },
    { to: '/alerts', label: 'Alerts', icon: AlertTriangle },
    { to: '/blocked-ips', label: 'Blocked IPs', icon: Ban },
    { to: '/traffic', label: 'Traffic Analysis', icon: Activity },
    { to: '/settings', label: 'Settings', icon: Settings },
    { to: '/model', label: 'ML Model Info', icon: BrainCircuit },
  ];

  return (
    <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col h-screen sticky top-0">
      {/* Brand header */}
      <div className="p-5 border-b border-slate-800 flex items-center gap-3">
        <div className="p-2 bg-blue-600/20 border border-blue-500/40 rounded-xl text-blue-400">
          <ShieldAlert className="w-6 h-6" />
        </div>
        <div>
          <h1 className="font-bold text-slate-100 tracking-tight leading-none">SAGEDRAL-ML</h1>
          <span className="text-[10px] text-blue-400 font-mono">NIDPS v1.0.0</span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
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

      {/* Footer */}
      <div className="p-4 border-t border-slate-800 text-xs text-slate-500">
        <p>Smart Adaptive Guardian</p>
        <p className="text-[10px] text-slate-600 mt-0.5">Machine Learning IPS</p>
      </div>
    </aside>
  );
}
