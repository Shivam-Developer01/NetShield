import api from './api';

export const getHealth = async () => {
  // Try GET /api/health first, fallback to root /health if needed
  try {
    return await api.get('/health');
  } catch (err) {
    return await api.get('/health');
  }
};

export const getMetrics = async (params = {}) => {
  const queryParams = new URLSearchParams();
  if (params.datasetType && params.datasetType !== 'all') {
    queryParams.append('datasetType', params.datasetType);
  }
  const url = `/metrics${queryParams.toString() ? '?' + queryParams.toString() : ''}`;
  return await api.get(url);
};

export const getPredictions = async (params = {}) => {
  const queryParams = new URLSearchParams();
  if (params.page) queryParams.append('page', params.page);
  if (params.limit) queryParams.append('limit', params.limit);
  if (params.datasetType && params.datasetType !== 'all') queryParams.append('datasetType', params.datasetType);
  if (params.prediction && params.prediction !== 'all') queryParams.append('prediction', params.prediction);
  if (params.startDate) queryParams.append('startDate', params.startDate);
  if (params.endDate) queryParams.append('endDate', params.endDate);

  const url = `/predictions${queryParams.toString() ? '?' + queryParams.toString() : ''}`;
  return await api.get(url);
};

export const getAlerts = async (params = {}) => {
  const queryParams = new URLSearchParams();
  if (params.page) queryParams.append('page', params.page);
  if (params.limit) queryParams.append('limit', params.limit);
  if (params.datasetType && params.datasetType !== 'all') queryParams.append('datasetType', params.datasetType);
  if (params.attackType && params.attackType !== 'all') queryParams.append('attackType', params.attackType);
  if (params.severity && params.severity !== 'all') queryParams.append('severity', params.severity);
  if (params.status && params.status !== 'all') queryParams.append('status', params.status);
  if (params.startDate) queryParams.append('startDate', params.startDate);
  if (params.endDate) queryParams.append('endDate', params.endDate);

  const url = `/alerts${queryParams.toString() ? '?' + queryParams.toString() : ''}`;
  return await api.get(url);
};

export const getAlertById = async (id) => {
  return await api.get(`/alerts/${id}`);
};

export const updateAlertStatus = async (id, status) => {
  return await api.patch(`/alerts/${id}`, { status });
};

export const submitPrediction = async (payload) => {
  return await api.post('/predictions', payload);
};

export const getSettings = async () => {
  return await api.get('/settings');
};

export const updateSetting = async (key, value, description) => {
  return await api.patch(`/settings/${key}`, { value, description });
};

export const getModelInfo = async () => {
  return await api.get('/analytics/model-info');
};

export const getOperationalHealth = async () => {
  return await getHealth();
};

export const getOperationalMetrics = async () => {
  const backendRoot = (api.defaults.baseURL || 'http://localhost:5000/api').replace(/\/api\/?$/, '');
  const res = await api.get(`${backendRoot}/metrics/json`);
  return res?.data || res;
};

export const getOperationalIncidents = async (params = {}) => {
  const queryParams = new URLSearchParams();
  if (params.limit) queryParams.append('limit', params.limit);
  if (params.status && params.status !== 'ALL') queryParams.append('status', params.status);
  if (params.severity && params.severity !== 'ALL') queryParams.append('severity', params.severity);

  const url = `/operations/incidents${queryParams.toString() ? '?' + queryParams.toString() : ''}`;
  const res = await api.get(url);
  return res?.data || res || [];
};

export const updateOperationalIncidentStatus = async (id, status) => {
  return await api.patch(`/operations/incidents/${id}`, { status });
};

