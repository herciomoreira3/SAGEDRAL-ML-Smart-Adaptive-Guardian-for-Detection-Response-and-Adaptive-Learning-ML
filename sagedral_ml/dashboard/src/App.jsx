import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { Layout } from './components/Layout';
import { ProtectedRoute, RoleRoute } from './components/ProtectedRoute';
import { Login } from './pages/Login';
import { Overview } from './pages/Overview';
import { Alerts } from './pages/Alerts';
import { BlockedIPs } from './pages/BlockedIPs';
import { Traffic } from './pages/Traffic';
import { Settings } from './pages/Settings';
import { ModelInfo } from './pages/ModelInfo';
import { Audit } from './pages/Audit';
import { Users } from './pages/Users';

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
                  <Route path="/settings" element={<RoleRoute roles={['admin']}><Settings /></RoleRoute>} />
                  <Route path="/model" element={<ModelInfo />} />
                  <Route path="/audit" element={<RoleRoute roles={['admin']}><Audit /></RoleRoute>} />
                  <Route path="/users" element={<RoleRoute roles={['admin']}><Users /></RoleRoute>} />
                </Routes>
              </Layout>
            </ProtectedRoute>
          }
        />
      </Routes>
    </BrowserRouter>
  );
}
