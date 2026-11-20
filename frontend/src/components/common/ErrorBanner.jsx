import React from 'react';
import { AlertCircle, RefreshCw } from 'lucide-react';

const ErrorBanner = ({ message, onRetry, title = 'Service Connection Error' }) => {
  return (
    <div style={{
      background: 'rgba(244, 63, 94, 0.12)',
      border: '1px solid rgba(244, 63, 94, 0.35)',
      borderRadius: '10px',
      padding: '1.25rem',
      margin: '1rem 0',
      display: 'flex',
      alignItems: 'flex-start',
      gap: '1rem',
      color: '#f87171'
    }}>
      <AlertCircle size={24} style={{ flexShrink: 0, marginTop: '2px' }} />
      <div style={{ flex: 1 }}>
        <h4 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 600, color: '#fda4af' }}>{title}</h4>
        <p style={{ margin: '0.35rem 0 0 0', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
          {message || 'Failed to fetch security telemetry from the NetShield Node.js backend.'}
        </p>
      </div>
      {onRetry && (
        <button 
          onClick={onRetry}
          className="btn"
          style={{ borderColor: 'rgba(244, 63, 94, 0.4)', color: '#fda4af', padding: '0.4rem 0.85rem' }}
        >
          <RefreshCw size={14} />
          Retry
        </button>
      )}
    </div>
  );
};

export default ErrorBanner;
