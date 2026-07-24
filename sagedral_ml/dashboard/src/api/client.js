import axios from 'axios';

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const getStatus = () => api.get('/status').then(res => res.data);
export const getAlerts = (params) => api.get('/alerts', { params }).then(res => res.data);
export const getBlockedIPs = () => api.get('/blocked-ips').then(res => res.data);
export const blockIP = (data) => api.post('/blocked-ips', data).then(res => res.data);
export const unblockIP = (ip) => api.delete(`/blocked-ips/${ip}`).then(res => res.data);
export const getTrafficStats = (params) => api.get('/traffic/stats', { params }).then(res => res.data);
export const getConfig = () => api.get('/config').then(res => res.data);
export const updateConfig = (data) => api.put('/config', { config: data }).then(res => res.data);
export const getModelInfo = () => api.get('/model/info').then(res => res.data);
export const createRule = (data) => api.post('/rules', data).then(res => res.data);

export default api;
