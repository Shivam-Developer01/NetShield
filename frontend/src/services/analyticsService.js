import api from './api';

export const getOverview = (params = {}) => api.get('/analytics/overview', { params });
export const getTrends = (params = {}) => api.get('/analytics/trends', { params });
export const getAttacks = (params = {}) => api.get('/analytics/attacks', { params });
export const getSeverity = (params = {}) => api.get('/analytics/severity', { params });
export const getModels = (params = {}) => api.get('/analytics/models', { params });
export const getAlertAnalytics = (params = {}) => api.get('/analytics/alerts', { params });

export const getInvestigation = (id) => api.get(`/investigations/alerts/${id}`);
export const getRelatedActivity = (id, timeWindowMinutes = 15) => 
  api.get(`/investigations/alerts/${id}/activity`, { params: { timeWindowMinutes } });

export const downloadExport = async (params = {}) => {
  const queryStr = new URLSearchParams(params).toString();
  const exportUrl = `${import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000/api'}/analytics/export?${queryStr}`;
  
  // Use window.open or hidden anchor for browser CSV download with HTTP-only cookies
  const link = document.createElement('a');
  link.href = exportUrl;
  link.setAttribute('download', `netshield_${params.type || 'export'}_${Date.now()}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
};
