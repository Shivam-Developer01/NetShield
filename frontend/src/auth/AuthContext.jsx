import React, { createContext, useContext, useState, useEffect } from 'react';
import { getMe, loginUser, logoutUser, getCsrfToken } from '../services/authService';
import { setCsrfToken, getStoredCsrfToken } from '../services/api';
import { connectSocket, disconnectSocket, addStatusListener } from '../services/socket';

export const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [socketStatus, setSocketStatus] = useState('disconnected');

  const checkAuth = async () => {
    try {
      const res = await getMe();
      if (res && res.success && res.user) {
        setUser(res.user);
        if (!getStoredCsrfToken() && typeof getCsrfToken === 'function') {
          try {
            const csrfPromise = getCsrfToken();
            if (csrfPromise && typeof csrfPromise.then === 'function') {
              csrfPromise.then(csrfRes => {
                if (csrfRes?.csrfToken) setCsrfToken(csrfRes.csrfToken);
              }).catch(() => {});
            }
          } catch {
            // Ignore in mocked test environment
          }
        }
      } else {
        setUser(null);
      }
    } catch (err) {
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkAuth();
  }, []);

  useEffect(() => {
    if (user) {
      connectSocket();
      const unsubscribe = addStatusListener((status) => {
        setSocketStatus(status);
      });
      return () => {
        if (typeof unsubscribe === 'function') {
          unsubscribe();
        }
      };
    } else {
      disconnectSocket();
      setSocketStatus('disconnected');
    }
  }, [user]);

  const login = async (email, password) => {
    const res = await loginUser(email, password);
    if (res.success && res.user) {
      setUser(res.user);
      if (res.csrfToken) {
        setCsrfToken(res.csrfToken);
      }
    }
    return res;
  };

  const logout = async () => {
    await logoutUser();
    disconnectSocket();
    setUser(null);
    setCsrfToken(null);
  };

  const value = {
    user,
    role: user?.role || null,
    isAuthenticated: !!user,
    loading,
    socketStatus,
    login,
    logout,
    checkAuth
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
