import React from 'react';
import { useLocation } from 'react-router-dom';
import { Activity, Database, Cpu, RefreshCw, Filter, User, LogOut } from 'lucide-react';
import { useAuth } from '../../auth/AuthContext';
import ConnectionStatusBadge from '../common/ConnectionStatusBadge';

const Header = ({ 
  healthStatus, 
  datasetFilter, 
  setDatasetFilter, 
  onRefresh, 
  lastUpdated 
}) => {
  const location = useLocation();
  const isDashboard = location.pathname === '/' || location.pathname === '/dashboard';
  const { user, role, logout } = useAuth();
  const isHealthy = healthStatus?.status === 'healthy';

  const getRoleBadgeStyle = (userRole) => {
    switch (userRole) {
      case 'ADMIN':
        return { bg: 'rgba(244, 63, 94, 0.15)', text: '#f87171', border: 'rgba(244, 63, 94, 0.3)' };
      case 'ANALYST':
        return { bg: 'rgba(245, 158, 11, 0.15)', text: '#fbbf24', border: 'rgba(245, 158, 11, 0.3)' };
      case 'VIEWER':
      default:
        return { bg: 'rgba(59, 130, 246, 0.15)', text: '#60a5fa', border: 'rgba(59, 130, 246, 0.3)' };
    }
  };

  const roleStyle = getRoleBadgeStyle(role);

  return (
    <header style={{
      background: 'rgba(15, 23, 42, 0.8)',
      backdropFilter: 'blur(10px)',
      borderBottom: '1px solid var(--border-color)',
      padding: '0.85rem 1.75rem',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      flexWrap: 'wrap',
      gap: '1rem'
    }}>
      {/* Title & Status Indicator */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
        <div>
          <h2 style={{ fontSize: '1.2rem', fontWeight: 700, color: '#f8fafc', margin: 0 }}>
            Cybersecurity Operations Center
          </h2>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', margin: '0.1rem 0 0 0' }}>
            Real-time Intrusion Detection & Threat Telemetry
          </p>
        </div>

        {/* Status Pills */}
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <ConnectionStatusBadge />

          <div className="badge" style={{
            background: isHealthy ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)',
            color: isHealthy ? '#34d399' : '#f87171',
            border: `1px solid ${isHealthy ? 'rgba(16, 185, 129, 0.3)' : 'rgba(244, 63, 94, 0.3)'}`
          }}>
            <Activity size={12} />
            Backend: {isHealthy ? 'Healthy' : 'Degraded'}
          </div>

          {healthStatus?.database && (
            <div className="badge" style={{
              background: healthStatus.database.status === 'connected' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(245, 158, 11, 0.15)',
              color: healthStatus.database.status === 'connected' ? '#34d399' : '#fbbf24',
              border: '1px solid rgba(255, 255, 255, 0.1)'
            }}>
              <Database size={12} />
              DB: {healthStatus.database.status}
            </div>
          )}

          {healthStatus?.ml_service && (
            <div className="badge" style={{
              background: healthStatus.ml_service.status === 'healthy' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)',
              color: healthStatus.ml_service.status === 'healthy' ? '#34d399' : '#f87171',
              border: '1px solid rgba(255, 255, 255, 0.1)'
            }}>
              <Cpu size={12} />
              ML Engine: {healthStatus.ml_service.status}
            </div>
          )}
        </div>
      </div>

      {/* Dataset Filter & User Session Controls */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
        {isDashboard && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <Filter size={14} style={{ color: 'var(--text-muted)' }} />
            <select 
              value={datasetFilter} 
              onChange={(e) => setDatasetFilter(e.target.value)}
              className="form-select"
              aria-label="Dataset Filter"
              style={{ padding: '0.35rem 0.65rem', fontSize: '0.775rem' }}
            >
              <option value="all">All Datasets</option>
              <option value="nsl_kdd">NSL-KDD Benchmark</option>
              <option value="cicids2017">CICIDS2017 Network Flow</option>
            </select>
          </div>
        )}

        <button onClick={onRefresh} className="btn" aria-label="Refresh telemetry" style={{ padding: '0.35rem 0.65rem', fontSize: '0.775rem' }}>
          <RefreshCw size={13} />
        </button>

        {/* User Session Info Pill & Logout */}
        {user && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.65rem',
            background: 'rgba(30, 41, 59, 0.6)',
            padding: '0.35rem 0.75rem',
            borderRadius: '8px',
            border: '1px solid var(--border-color)'
          }}>
            <User size={14} style={{ color: 'var(--accent-cyan)' }} />
            <div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#f8fafc' }}>
              {user.username}
            </div>

            <span className="badge" style={{
              background: roleStyle.bg,
              color: roleStyle.text,
              border: `1px solid ${roleStyle.border}`,
              padding: '0.15rem 0.45rem',
              fontSize: '0.65rem'
            }}>
              {role}
            </span>

            <button
              onClick={logout}
              className="btn"
              title="Logout session"
              style={{
                padding: '0.25rem 0.45rem',
                fontSize: '0.7rem',
                borderColor: 'rgba(244, 63, 94, 0.4)',
                color: '#f87171'
              }}
            >
              <LogOut size={13} />
            </button>
          </div>
        )}
      </div>
    </header>
  );
};

export default Header;
