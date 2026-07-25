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
export const getStatus = () => api.get('/status').then(res => res.data);
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

export default api;
