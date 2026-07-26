import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';

export function ProtectedRoute({ children }) {
  const location = useLocation();
  const token = localStorage.getItem('sagedral_token');

  if (!token) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return children;
}

export function RoleRoute({ roles, children }) {
  let user = {};
  try {
    user = JSON.parse(localStorage.getItem('sagedral_user') || '{}');
  } catch {
    user = {};
  }
  if (!roles.includes(user.role)) {
    return <Navigate to="/" replace />;
  }
  return children;
}

export default ProtectedRoute;
