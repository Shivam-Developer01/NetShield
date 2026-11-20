import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000/api';

// Helper to parse cookie value from document.cookie
export const getCsrfCookie = () => {
  if (typeof document === 'undefined') return null;
  const match = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : null;
};

// In-memory fallback if cookies are restricted or mocked in tests
let inMemoryCsrfToken = null;
export const setCsrfToken = (token) => {
  inMemoryCsrfToken = token;
  if (typeof sessionStorage !== 'undefined' && token) {
    try {
      sessionStorage.setItem('netshield_csrf_token', token);
    } catch {
      // Ignore quota or security errors in iframe/private browsing
    }
  }
};

export const getStoredCsrfToken = () => {
  return (
    getCsrfCookie() ||
    inMemoryCsrfToken ||
    (typeof sessionStorage !== 'undefined' ? sessionStorage.getItem('netshield_csrf_token') : null)
  );
};

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  withCredentials: true, // Enables sending HTTP-only authentication cookies cross-origin
  withXSRFToken: true, // Enables sending CSRF token header cross-origin in Axios 1.7+
  xsrfCookieName: 'XSRF-TOKEN', // Automatically reads readable CSRF cookie
  xsrfHeaderName: 'X-XSRF-TOKEN', // Automatically attaches CSRF token header on POST/PATCH/DELETE
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  }
});

// Centralized Request Interceptor to guarantee X-XSRF-TOKEN is attached on state-changing requests
api.interceptors.request.use(
  (config) => {
    const method = (config.method || '').toUpperCase();
    const stateChangingMethods = ['POST', 'PUT', 'PATCH', 'DELETE'];

    if (stateChangingMethods.includes(method)) {
      const token = getStoredCsrfToken();
      if (token) {
        if (config.headers && typeof config.headers.set === 'function') {
          config.headers.set('X-XSRF-TOKEN', token);
        } else {
          config.headers = config.headers || {};
          config.headers['X-XSRF-TOKEN'] = token;
        }
      }
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor for consistent error extraction and auth redirects
api.interceptors.response.use(
  (response) => {
    // Automatically capture and cache csrfToken if returned in response data
    if (response.data && response.data.csrfToken) {
      setCsrfToken(response.data.csrfToken);
    }
    return response.data;
  },
  (error) => {
    let errorMessage = 'Network error or backend service unavailable.';
    let status = 503;

    if (error.response) {
      status = error.response.status;
      errorMessage = error.response.data?.error?.message 
        || error.response.data?.message 
        || `Server returned HTTP ${status}`;
    } else if (error.request) {
      errorMessage = 'Backend service connection failed. Please ensure Node.js server is running on port 5000.';
    } else {
      errorMessage = error.message;
    }

    const err = new Error(errorMessage);
    err.status = status;
    return Promise.reject(err);
  }
);

export default api;
