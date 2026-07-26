import axios from 'axios';

const getToken = () => localStorage.getItem('sagedral_token');

const clearAuthAndRedirect = () => {
  localStorage.removeItem('sagedral_token');
  if (typeof window !== 'undefined' && window.location.pathname !== '/login') {
    window.location.href = '/login';
  }
};

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.request.use(
  (config) => {
    const token = getToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      clearAuthAndRedirect();
    }
    return Promise.reject(error);
  }
);

export const login = (data) => api.post('/auth/login', data).then(res => res.data);
export const logout = () => api.post('/auth/logout').then(res => res.data);
export const getStatus = () => api.get('/status/details').then(res => res.data);
export const getAlerts = (params) => api.get('/alerts', { params }).then(res => res.data);
export const getBlockedIPs = () => api.get('/blocked-ips').then(res => res.data);
export const blockIP = (data) => api.post('/blocked-ips', data).then(res => res.data);
export const unblockIP = (ip) => api.delete(`/blocked-ips/${ip}`).then(res => res.data);
export const getTrafficStats = (params) => api.get('/traffic/stats', { params }).then(res => res.data);
export const getConfig = () => api.get('/config').then(res => res.data);
export const updateConfig = (data) => api.put('/config', { config: data }).then(res => res.data);
export const getModelInfo = () => api.get('/model/info').then(res => res.data);
export const getCaptureStats = () => api.get('/capture/stats').then(res => res.data);
export const createRule = (data) => api.post('/rules', data).then(res => res.data);
export const getWhitelist = () => api.get('/blocked-ips/whitelist').then(res => res.data);
export const addWhitelist = (data) => api.post('/blocked-ips/whitelist', data).then(res => res.data);
export const removeWhitelist = (entry) => api.delete(`/blocked-ips/whitelist/${encodeURIComponent(entry)}`).then(res => res.data);
export const submitAlertFeedback = (alertId, data) => api.post(`/alerts/${alertId}/feedback`, data).then(res => res.data);
export const closeAlert = (alertId) => api.post(`/alerts/${alertId}/close`).then(res => res.data);
export const deleteAlert = (alertId) => api.delete(`/alerts/${alertId}`).then(res => res.data);
export const getAuditLogs = (params) => api.get('/audit-logs', { params }).then(res => res.data);
export const getUsers = () => api.get('/users').then(res => res.data);
export const createUser = (data) => api.post('/users', data).then(res => res.data);
export const updateUser = (userId, data) => api.put(`/users/${userId}`, data).then(res => res.data);
export const deleteUser = (userId) => api.delete(`/users/${userId}`).then(res => res.data);
export const getModelDrift = () => api.get('/model/drift').then(res => res.data);

export const downloadAlertsCSV = async (params = {}) => {
  const response = await api.get('/alerts/export.csv', { params, responseType: 'blob' });
  const url = URL.createObjectURL(response.data);
  const link = document.createElement('a');
  link.href = url;
  link.download = `sagedral-alerts-${Date.now()}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
};

export default api;
