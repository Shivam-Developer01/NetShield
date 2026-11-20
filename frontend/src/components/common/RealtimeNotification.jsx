import React, { useState, useEffect } from 'react';
import { AlertTriangle, Info, X } from 'lucide-react';
import { subscribeToEvent } from '../../services/socket';

const RealtimeNotification = () => {
  const [notifications, setNotifications] = useState([]);

  useEffect(() => {
    const removeAlertSub = subscribeToEvent('alert.created', (envelope) => {
      const alertData = envelope.data || {};
      const newNotif = {
        id: envelope.requestId || Date.now() + Math.random(),
        type: 'alert',
        title: `Security Alert: ${alertData.prediction || 'Threat Detected'}`,
        message: alertData.description || `Severity: ${alertData.severity?.toUpperCase()} | Dataset: ${alertData.datasetType}`,
        severity: alertData.severity || 'high',
        timestamp: envelope.timestamp || new Date().toISOString()
      };
      setNotifications((prev) => [newNotif, ...prev].slice(0, 5));
    });

    const removeNotifSub = subscribeToEvent('system.notification', (envelope) => {
      const data = envelope.data || {};
      const newNotif = {
        id: envelope.requestId || Date.now() + Math.random(),
        type: 'system',
        title: data.title || 'System Notification',
        message: data.message || 'System update received.',
        severity: data.level || 'info',
        timestamp: envelope.timestamp || new Date().toISOString()
      };
      setNotifications((prev) => [newNotif, ...prev].slice(0, 5));
    });

    return () => {
      if (typeof removeAlertSub === 'function') removeAlertSub();
      if (typeof removeNotifSub === 'function') removeNotifSub();
    };
  }, []);

  const dismiss = (id) => {
    setNotifications((prev) => prev.filter((n) => n.id !== id));
  };

  if (notifications.length === 0) return null;

  return (
    <div
      style={{
        position: 'fixed',
        top: '1.25rem',
        right: '1.25rem',
        zIndex: 9999,
        display: 'flex',
        flexDirection: 'column',
        gap: '0.65rem',
        maxWidth: '380px',
        width: '100%',
        pointerEvents: 'none'
      }}
    >
      {notifications.map((notif) => {
        const isCritical = notif.severity === 'critical' || notif.severity === 'high';
        const bg = isCritical ? 'rgba(30, 27, 38, 0.95)' : 'rgba(15, 23, 42, 0.95)';
        const border = isCritical ? '#f87171' : '#38bdf8';
        const color = isCritical ? '#f87171' : '#38bdf8';

        return (
          <div
            key={notif.id}
            style={{
              pointerEvents: 'auto',
              background: bg,
              borderLeft: `4px solid ${border}`,
              borderTop: '1px solid rgba(255,255,255,0.1)',
              borderRight: '1px solid rgba(255,255,255,0.1)',
              borderBottom: '1px solid rgba(255,255,255,0.1)',
              borderRadius: '8px',
              padding: '0.85rem 1rem',
              boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.5)',
              backdropFilter: 'blur(12px)',
              display: 'flex',
              alignItems: 'flex-start',
              gap: '0.75rem',
              animation: 'fadeInRight 0.3s ease-out'
            }}
          >
            {isCritical ? <AlertTriangle size={18} style={{ color, flexShrink: 0, marginTop: '2px' }} /> : <Info size={18} style={{ color, flexShrink: 0, marginTop: '2px' }} />}
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#f8fafc', marginBottom: '0.2rem' }}>
                {notif.title}
              </div>
              <div style={{ fontSize: '0.775rem', color: 'var(--text-muted)', lineHeight: 1.35 }}>
                {notif.message}
              </div>
            </div>
            <button
              onClick={() => dismiss(notif.id)}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                padding: '2px',
                display: 'flex',
                alignItems: 'center'
              }}
            >
              <X size={14} />
            </button>
          </div>
        );
      })}
    </div>
  );
};

export default RealtimeNotification;
