import api from './api';

export const getCsrfToken = async () => {
  return await api.get('/auth/csrf');
};

export const loginUser = async (email, password) => {
  return await api.post('/auth/login', { email, password });
};

export const registerUser = async (userData) => {
  return await api.post('/auth/register', userData);
};

export const logoutUser = async () => {
  try {
    await api.post('/auth/logout');
  } catch (err) {
    // Ignore network error on logout
  }
};

export const getMe = async () => {
  return await api.get('/auth/me');
};

export const getUsers = async (params = {}) => {
  const queryParams = new URLSearchParams();
  if (params.page) queryParams.append('page', params.page);
  if (params.limit) queryParams.append('limit', params.limit);
  if (params.role && params.role !== 'all') queryParams.append('role', params.role);
  if (params.isActive !== undefined && params.isActive !== 'all') queryParams.append('isActive', params.isActive);

  const url = `/users${queryParams.toString() ? '?' + queryParams.toString() : ''}`;
  return await api.get(url);
};

export const updateUser = async (id, data) => {
  return await api.patch(`/users/${id}`, data);
};

export const deleteUser = async (id) => {
  return await api.delete(`/users/${id}`);
};
