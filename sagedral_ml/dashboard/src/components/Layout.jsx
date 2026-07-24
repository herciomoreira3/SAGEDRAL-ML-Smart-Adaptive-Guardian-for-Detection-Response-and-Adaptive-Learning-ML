import React from 'react';
import { Sidebar } from './Sidebar';
import { useWebSocket } from '../hooks/useWebSocket';
import { Wifi, WifiOff } from 'lucide-react';

export function Layout({ children }) {
  const { connected } = useWebSocket();

  return (
    <div className="flex min-h-screen bg-slate-950">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top bar */}
        <header className="h-16 border-b border-slate-800 bg-slate-900/50 backdrop-blur px-6 flex items-center justify-between sticky top-0 z-10">
          <h2 className="text-sm font-semibold text-slate-300">Live Security Operations Center</h2>
          <div className="flex items-center gap-3">
            <div className={`flex items-center gap-2 px-3 py-1 rounded-full text-xs font-medium border ${
              connected 
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' 
                : 'bg-red-500/10 text-red-400 border-red-500/30'
            }`}>
              {connected ? <Wifi className="w-3.5 h-3.5" /> : <WifiOff className="w-3.5 h-3.5" />}
              {connected ? 'WebSocket Connected' : 'Disconnected'}
            </div>
          </div>
        </header>

        {/* Main Content */}
        <main className="p-6 flex-1 overflow-x-hidden">
          {children}
        </main>
      </div>
    </div>
  );
}
