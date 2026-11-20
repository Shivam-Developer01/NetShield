import React from 'react';
import { Wifi, WifiOff, RefreshCw } from 'lucide-react';
import { useAuth } from '../../auth/AuthContext';

const ConnectionStatusBadge = () => {
  const { socketStatus } = useAuth();

  const getStatusConfig = () => {
    switch (socketStatus) {
      case 'connected':
        return {
          bg: 'rgba(16, 185, 129, 0.15)',
          text: '#34d399',
          border: 'rgba(16, 185, 129, 0.3)',
          label: 'WS LIVE',
          icon: <Wifi size={12} className="animate-pulse" />
        };
      case 'connecting':
      case 'reconnecting':
        return {
          bg: 'rgba(245, 158, 11, 0.15)',
          text: '#fbbf24',
          border: 'rgba(245, 158, 11, 0.3)',
          label: socketStatus === 'reconnecting' ? 'RECONNECTING' : 'CONNECTING',
          icon: <RefreshCw size={12} style={{ animation: 'spin 1.5s linear infinite' }} />
        };
      case 'disconnected':
      default:
        return {
          bg: 'rgba(100, 116, 139, 0.15)',
          text: '#94a3b8',
          border: 'rgba(100, 116, 139, 0.3)',
          label: 'REST FALLBACK',
          icon: <WifiOff size={12} />
        };
    }
  };

  const config = getStatusConfig();

  return (
    <div
      className="badge"
      title={`Real-time WebSocket Streaming: ${(socketStatus || 'disconnected').toUpperCase()}`}
      style={{
        background: config.bg,
        color: config.text,
        border: `1px solid ${config.border}`,
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.35rem',
        padding: '0.25rem 0.6rem',
        fontSize: '0.7rem',
        fontWeight: 600,
        borderRadius: '9999px',
        letterSpacing: '0.02em'
      }}
    >
      {config.icon}
      <span>{config.label}</span>
    </div>
  );
};

export default ConnectionStatusBadge;
