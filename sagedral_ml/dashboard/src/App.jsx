import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { Layout } from './components/Layout';
import { ProtectedRoute } from './components/ProtectedRoute';
import { Login } from './pages/Login';
import { Overview } from './pages/Overview';
import { Alerts } from './pages/Alerts';
import { BlockedIPs } from './pages/BlockedIPs';
import { Traffic } from './pages/Traffic';
import { Settings } from './pages/Settings';
import { ModelInfo } from './pages/ModelInfo';

export default function App() {
  return (
    <BrowserRouter>
      <Toaster 
        position="top-right"
        toastOptions={{
          style: {
            background: '#0f172a',
            color: '#f8fafc',
            border: '1px solid #334155',
            fontSize: '12px',
          },
        }}
      />
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="*"
          element={
            <ProtectedRoute>
              <Layout>
                <Routes>
                  <Route path="/" element={<Overview />} />
                  <Route path="/alerts" element={<Alerts />} />
                  <Route path="/blocked-ips" element={<BlockedIPs />} />
                  <Route path="/traffic" element={<Traffic />} />
                  <Route path="/settings" element={<Settings />} />
                  <Route path="/model" element={<ModelInfo />} />
                </Routes>
              </Layout>
            </ProtectedRoute>
          }
        />
      </Routes>
    </BrowserRouter>
  );
}
