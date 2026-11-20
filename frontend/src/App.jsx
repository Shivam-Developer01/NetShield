import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Sidebar from './components/layout/Sidebar';
import Header from './components/layout/Header';
import RealtimeNotification from './components/common/RealtimeNotification';
import DashboardPage from './pages/DashboardPage';
import AnalyticsPage from './pages/AnalyticsPage';
import AlertInvestigationPage from './pages/AlertInvestigationPage';
import ThreatsPage from './pages/ThreatsPage';
import AlertsPage from './pages/AlertsPage';
import PredictPage from './pages/PredictPage';
import MetricsPage from './pages/MetricsPage';
import SettingsPage from './pages/SettingsPage';
import UsersPage from './pages/UsersPage';
import OperationsPage from './pages/OperationsPage';
import LoginPage from './pages/LoginPage';
import { AuthProvider, useAuth } from './auth/AuthContext';
import ProtectedRoute from './auth/ProtectedRoute';
import { getHealth } from './services/socService';

const AppContent = () => {
  const { role: userRole } = useAuth();
  const [healthStatus, setHealthStatus] = useState(null);
  const [datasetFilter, setDatasetFilter] = useState('all');
  const [lastUpdated, setLastUpdated] = useState(new Date().toISOString());

  const checkStatus = async () => {
    try {
      const res = await getHealth();
      setHealthStatus(res);
    } catch (err) {
      setHealthStatus({ status: 'degraded', error: err.message });
    }
  };

  useEffect(() => {
    checkStatus();
    const interval = setInterval(checkStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleRefresh = () => {
    setLastUpdated(new Date().toISOString());
    checkStatus();
  };

  return (
    <div className="app-container">
      <RealtimeNotification />
      <Sidebar />
      <div className="main-wrapper">
        <Header 
          healthStatus={healthStatus}
          datasetFilter={datasetFilter}
          setDatasetFilter={setDatasetFilter}
          onRefresh={handleRefresh}
          lastUpdated={lastUpdated}
        />
        <main className="page-content">
          <Routes>
            <Route 
              path="/" 
              element={
                <ProtectedRoute allowedRoles={['ADMIN', 'ANALYST', 'VIEWER']}>
                  <DashboardPage datasetFilter={datasetFilter} onDataRefreshed={handleRefresh} />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/dashboard" 
              element={
                <ProtectedRoute allowedRoles={['ADMIN', 'ANALYST', 'VIEWER']}>
                  <DashboardPage datasetFilter={datasetFilter} onDataRefreshed={handleRefresh} />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/analytics" 
              element={
                <ProtectedRoute allowedRoles={['ADMIN', 'ANALYST', 'VIEWER']}>
                  <AnalyticsPage globalDatasetFilter={datasetFilter} />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/alerts/:id/investigate" 
              element={
                <ProtectedRoute allowedRoles={['ADMIN', 'ANALYST', 'VIEWER']}>
                  <AlertInvestigationPage />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/threats" 
              element={
                <ProtectedRoute allowedRoles={['ADMIN', 'ANALYST', 'VIEWER']}>
                  <ThreatsPage globalDatasetFilter={datasetFilter} />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/alerts" 
              element={
                <ProtectedRoute allowedRoles={['ADMIN', 'ANALYST', 'VIEWER']}>
                  <AlertsPage globalDatasetFilter={datasetFilter} />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/predict" 
              element={
                <ProtectedRoute allowedRoles={['ADMIN', 'ANALYST', 'VIEWER']}>
                  <PredictPage />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/operations" 
              element={
                <ProtectedRoute allowedRoles={['ADMIN', 'ANALYST', 'VIEWER']}>
                  <OperationsPage userRole={userRole} />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/metrics" 
              element={
                <ProtectedRoute allowedRoles={['ADMIN', 'ANALYST', 'VIEWER']}>
                  <MetricsPage />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/settings" 
              element={
                <ProtectedRoute allowedRoles={['ADMIN', 'ANALYST', 'VIEWER']}>
                  <SettingsPage />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/users" 
              element={
                <ProtectedRoute allowedRoles={['ADMIN']}>
                  <UsersPage />
                </ProtectedRoute>
              } 
            />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
};

const App = () => {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/*" element={<AppContent />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
};

export default App;
