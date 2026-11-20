import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, 
  ShieldAlert, 
  Activity, 
  Cpu, 
  BarChart3, 
  TrendingUp,
  Settings, 
  Shield,
  Users
} from 'lucide-react';
import { useAuth } from '../../auth/AuthContext';

const Sidebar = () => {
  const { role } = useAuth();

  const navItems = [
    { path: '/', label: 'Dashboard', icon: LayoutDashboard, roles: ['ADMIN', 'ANALYST', 'VIEWER'] },
    { path: '/operations', label: 'Operations & Health', icon: Activity, roles: ['ADMIN', 'ANALYST', 'VIEWER'] },
    { path: '/analytics', label: 'Analytics & SOC Intel', icon: TrendingUp, roles: ['ADMIN', 'ANALYST', 'VIEWER'] },
    { path: '/threats', label: 'Predictions & Feed', icon: Activity, roles: ['ADMIN', 'ANALYST', 'VIEWER'] },
    { path: '/alerts', label: 'Security Alerts', icon: ShieldAlert, roles: ['ADMIN', 'ANALYST', 'VIEWER'] },
    { path: '/predict', label: 'Manual Predict', icon: Cpu, roles: ['ADMIN', 'ANALYST', 'VIEWER'] },
    { path: '/metrics', label: 'System Metrics', icon: BarChart3, roles: ['ADMIN', 'ANALYST', 'VIEWER'] },
    { path: '/settings', label: 'Settings', icon: Settings, roles: ['ADMIN', 'ANALYST', 'VIEWER'] },
    { path: '/users', label: 'User Management', icon: Users, roles: ['ADMIN'] },
  ];

  const visibleItems = navItems.filter(item => !role || item.roles.includes(role));

  return (
    <aside style={{
      width: '240px',
      background: 'rgba(15, 23, 42, 0.95)',
      borderRight: '1px solid var(--border-color)',
      display: 'flex',
      flexDirection: 'column',
      flexShrink: 0
    }}>
      {/* Brand Header */}
      <div style={{
        padding: '1.5rem 1.25rem',
        borderBottom: '1px solid var(--border-color)',
        display: 'flex',
        alignItems: 'center',
        gap: '0.75rem'
      }}>
        <div style={{
          background: 'linear-gradient(135deg, #0284c7 0%, #00f2fe 100%)',
          padding: '0.4rem',
          borderRadius: '8px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: '0 0 12px rgba(0, 242, 254, 0.4)'
        }}>
          <Shield size={22} style={{ color: '#0f172a' }} />
        </div>
        <div>
          <h1 style={{ fontSize: '1.15rem', fontWeight: 800, letterSpacing: '0.05em', color: '#f8fafc' }}>
            NET<span style={{ color: 'var(--accent-cyan)' }}>SHIELD</span>
          </h1>
          <p style={{ fontSize: '0.65rem', fontWeight: 600, color: 'var(--text-muted)', letterSpacing: '0.08em' }}>
            SOC OPERATIONS
          </p>
        </div>
      </div>

      {/* Navigation Menu */}
      <nav style={{ padding: '1.25rem 0.75rem', flex: 1, display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
        {visibleItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
              style={({ isActive }) => ({
                display: 'flex',
                alignItems: 'center',
                gap: '0.75rem',
                padding: '0.7rem 0.85rem',
                borderRadius: '8px',
                fontSize: '0.875rem',
                fontWeight: isActive ? 600 : 500,
                color: isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                background: isActive ? 'rgba(0, 242, 254, 0.1)' : 'transparent',
                border: isActive ? '1px solid rgba(0, 242, 254, 0.25)' : '1px solid transparent',
                transition: 'all 0.2s ease'
              })}
            >
              <Icon size={18} />
              <span>{item.label}</span>
            </NavLink>
          );
        })}
      </nav>

      {/* Footer Info */}
      <div style={{
        padding: '1rem',
        borderTop: '1px solid var(--border-color)',
        fontSize: '0.75rem',
        color: 'var(--text-muted)'
      }}>
        <div>Version 1.0.0 (Phase 11)</div>
        <div style={{ fontSize: '0.7rem', color: '#475569', marginTop: '0.2rem' }}>RBAC Auth Enabled ({role || 'Guest'})</div>
      </div>
    </aside>
  );
};

export default Sidebar;
