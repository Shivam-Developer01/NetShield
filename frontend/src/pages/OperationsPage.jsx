import React, { useState, useEffect } from 'react';
import { 
  Activity, Server, Database, Cpu, Wifi, AlertTriangle, 
  CheckCircle, RefreshCw, Check, XCircle, ShieldAlert, Clock
} from 'lucide-react';
import { subscribeToEvent } from '../services/socket';
import { 
  getOperationalHealth, 
  getOperationalMetrics, 
  getOperationalIncidents, 
  updateOperationalIncidentStatus 
} from '../services/socService';

export default function OperationsPage({ userRole }) {
  const [healthData, setHealthData] = useState(null);
  const [metricsData, setMetricsData] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [actionLoading, setActionLoading] = useState(null);

  const canManageIncidents = ['ADMIN', 'ANALYST'].includes(userRole);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [hRes, mRes, iRes] = await Promise.allSettled([
        getOperationalHealth(),
        getOperationalMetrics(),
        getOperationalIncidents({ limit: 50 })
      ]);

      if (hRes.status === 'fulfilled' && hRes.value) {
        setHealthData(hRes.value);
      }
      if (mRes.status === 'fulfilled' && mRes.value) {
        const mData = mRes.value?.data || mRes.value;
        setMetricsData(mData);
      }
      if (iRes.status === 'fulfilled' && iRes.value) {
        const incList = Array.isArray(iRes.value) 
          ? iRes.value 
          : (iRes.value?.data || []);
        setIncidents(incList);
      }
    } catch (err) {
      console.error('Error loading operational monitoring data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();

    // Subscribe to Socket.IO real-time operational events
    const unsubHealth = subscribeToEvent('system.health.changed', (envelope) => {
      if (envelope?.data?.health) setHealthData(envelope.data.health);
    });

    const unsubCreated = subscribeToEvent('system.incident.created', (envelope) => {
      if (envelope?.data?.incident) {
        setIncidents(prev => [envelope.data.incident, ...prev]);
      }
    });

    const unsubUpdated = subscribeToEvent('system.incident.updated', (envelope) => {
      if (envelope?.data?.incident) {
        const updated = envelope.data.incident;
        setIncidents(prev => prev.map(inc => inc._id === updated._id ? updated : inc));
      }
    });

    return () => {
      if (typeof unsubHealth === 'function') unsubHealth();
      if (typeof unsubCreated === 'function') unsubCreated();
      if (typeof unsubUpdated === 'function') unsubUpdated();
    };
  }, []);

  const handleUpdateStatus = async (incidentId, newStatus) => {
    try {
      setActionLoading(incidentId);
      const res = await updateOperationalIncidentStatus(incidentId, newStatus);
      const updated = res?.data || res;
      if (updated && updated._id) {
        setIncidents(prev => prev.map(inc => inc._id === updated._id ? updated : inc));
      }
    } catch (err) {
      console.error('Failed to update incident status:', err);
    } finally {
      setActionLoading(null);
    }
  };

  const filteredIncidents = incidents.filter(inc => {
    if (filterSeverity !== 'ALL' && inc.severity !== filterSeverity) return false;
    if (filterStatus !== 'ALL' && inc.status !== filterStatus) return false;
    return true;
  });

  const getStatusBadgeStyle = (statusStr) => {
    switch (statusStr?.toLowerCase()) {
      case 'healthy':
        return {
          background: 'rgba(16, 185, 129, 0.15)',
          color: '#34d399',
          border: '1px solid rgba(16, 185, 129, 0.3)'
        };
      case 'degraded':
        return {
          background: 'rgba(245, 158, 11, 0.15)',
          color: '#fbbf24',
          border: '1px solid rgba(245, 158, 11, 0.3)'
        };
      case 'unhealthy':
        return {
          background: 'rgba(244, 63, 94, 0.15)',
          color: '#f87171',
          border: '1px solid rgba(244, 63, 94, 0.3)'
        };
      default:
        return {
          background: 'rgba(100, 116, 139, 0.15)',
          color: '#94a3b8',
          border: '1px solid rgba(100, 116, 139, 0.3)'
        };
    }
  };

  const getSeverityBadgeClass = (sev) => {
    switch (sev) {
      case 'CRITICAL': return 'badge badge-critical';
      case 'HIGH': return 'badge badge-high';
      case 'MEDIUM': return 'badge badge-medium';
      default: return 'badge badge-low';
    }
  };

  const getIncidentStatusBadgeStyle = (status) => {
    switch (status) {
      case 'OPEN':
        return {
          background: 'rgba(244, 63, 94, 0.15)',
          color: '#f87171',
          border: '1px solid rgba(244, 63, 94, 0.3)'
        };
      case 'ACKNOWLEDGED':
        return {
          background: 'rgba(245, 158, 11, 0.15)',
          color: '#fbbf24',
          border: '1px solid rgba(245, 158, 11, 0.3)'
        };
      case 'RESOLVED':
        return {
          background: 'rgba(16, 185, 129, 0.15)',
          color: '#34d399',
          border: '1px solid rgba(16, 185, 129, 0.3)'
        };
      default:
        return {
          background: 'rgba(100, 116, 139, 0.15)',
          color: '#94a3b8',
          border: '1px solid rgba(100, 116, 139, 0.3)'
        };
    }
  };

  const services = healthData?.services || {};

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '1rem',
        borderBottom: '1px solid var(--border-color)',
        paddingBottom: '1.25rem'
      }}>
        <div>
          <h2 style={{
            fontSize: '1.35rem',
            fontWeight: 700,
            color: '#f8fafc',
            display: 'flex',
            alignItems: 'center',
            gap: '0.6rem',
            margin: 0
          }}>
            <Activity size={22} style={{ color: 'var(--accent-cyan)' }} />
            Operations & Health Monitoring
          </h2>
          <p style={{ fontSize: '0.825rem', color: 'var(--text-muted)', margin: '0.25rem 0 0 0' }}>
            Real-time infrastructure health, operational metrics, and incident management
          </p>
        </div>
        <button
          onClick={fetchData}
          disabled={loading}
          className="btn"
          style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem' }}
        >
          <RefreshCw size={14} className={loading ? 'spin' : ''} />
          Refresh Status
        </button>
      </div>

      {/* Subsystem Health Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))',
        gap: '1.25rem'
      }}>
        {/* Node.js Backend */}
        <div className="soc-card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', minHeight: '130px', padding: '1.1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
              <Server size={16} style={{ color: 'var(--accent-cyan)' }} /> Backend
            </span>
            <span className="badge" style={getStatusBadgeStyle(services.backend?.status)}>
              {services.backend?.status?.toUpperCase() || 'UNKNOWN'}
            </span>
          </div>
          <div>
            <p style={{ fontSize: '0.85rem', fontWeight: 500, color: 'var(--text-primary)', margin: 0 }}>Node.js Express Server</p>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.35rem', fontFamily: 'var(--font-mono)' }}>
              Uptime: {services.backend?.uptimeSeconds ? `${services.backend.uptimeSeconds}s` : 'Unavailable'}
            </p>
          </div>
        </div>

        {/* MongoDB */}
        <div className="soc-card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', minHeight: '130px', padding: '1.1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
              <Database size={16} style={{ color: 'var(--accent-emerald)' }} /> MongoDB
            </span>
            <span className="badge" style={getStatusBadgeStyle(services.mongodb?.status)}>
              {services.mongodb?.status?.toUpperCase() || 'UNKNOWN'}
            </span>
          </div>
          <div>
            <p style={{ fontSize: '0.85rem', fontWeight: 500, color: 'var(--text-primary)', margin: 0 }}>Database Store</p>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.35rem', fontFamily: 'var(--font-mono)' }}>
              State: {services.mongodb?.state || 'Unavailable'}
            </p>
          </div>
        </div>

        {/* FastAPI ML Service */}
        <div className="soc-card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', minHeight: '130px', padding: '1.1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
              <Cpu size={16} style={{ color: 'var(--accent-purple)' }} /> ML Service
            </span>
            <span className="badge" style={getStatusBadgeStyle(services.mlService?.status)}>
              {services.mlService?.status?.toUpperCase() || 'UNKNOWN'}
            </span>
          </div>
          <div>
            <p style={{ fontSize: '0.85rem', fontWeight: 500, color: 'var(--text-primary)', margin: 0 }}>FastAPI Inference</p>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.35rem', fontFamily: 'var(--font-mono)' }}>
              Engine: XGBoost v1.0
            </p>
          </div>
        </div>

        {/* Network Sensor */}
        <div className="soc-card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', minHeight: '130px', padding: '1.1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
              <Activity size={16} style={{ color: 'var(--accent-amber)' }} /> Sensor
            </span>
            <span className="badge" style={getStatusBadgeStyle(services.sensor?.status)}>
              {services.sensor?.status?.toUpperCase() || 'UNKNOWN'}
            </span>
          </div>
          <div>
            <p style={{ fontSize: '0.85rem', fontWeight: 500, color: 'var(--text-primary)', margin: 0 }}>Scapy Capture</p>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.35rem', fontFamily: 'var(--font-mono)' }}>
              Last Seen: {services.sensor?.lastSeenAt ? new Date(services.sensor.lastSeenAt).toLocaleTimeString() : 'Unavailable'}
            </p>
          </div>
        </div>

        {/* Socket.IO */}
        <div className="soc-card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', minHeight: '130px', padding: '1.1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
              <Wifi size={16} style={{ color: 'var(--accent-blue)' }} /> WebSocket
            </span>
            <span className="badge" style={getStatusBadgeStyle(services.socket?.status)}>
              {services.socket?.status?.toUpperCase() || 'UNKNOWN'}
            </span>
          </div>
          <div>
            <p style={{ fontSize: '0.85rem', fontWeight: 500, color: 'var(--text-primary)', margin: 0 }}>Socket.IO Streamer</p>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.35rem', fontFamily: 'var(--font-mono)' }}>
              Connections: {services.socket?.activeConnections ?? 'Unavailable'}
            </p>
          </div>
        </div>
      </div>

      {/* Operational Metrics Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
        gap: '1.25rem'
      }}>
        <div className="soc-card kpi-card" style={{ padding: '1.1rem' }}>
          <div className="kpi-title">HTTP Requests Total</div>
          <div className="kpi-value">{metricsData?.http?.totalRequests ?? 'Unavailable'}</div>
          <div className="kpi-subtitle">
            Error Rate: {metricsData?.http?.errorRatePercent !== undefined ? `${metricsData.http.errorRatePercent}%` : 'Unavailable'}
          </div>
        </div>

        <div className="soc-card kpi-card" style={{ padding: '1.1rem' }}>
          <div className="kpi-title">API Latency (avg / p95)</div>
          <div className="kpi-value">
            {metricsData?.http?.latency?.avg !== undefined ? `${metricsData.http.latency.avg} ms / ${metricsData.http.latency.p95} ms` : 'Unavailable'}
          </div>
          <div className="kpi-subtitle">In-process HTTP tracker</div>
        </div>

        <div className="soc-card kpi-card" style={{ padding: '1.1rem' }}>
          <div className="kpi-title">ML Inference Total / Failures</div>
          <div className="kpi-value">
            {metricsData?.ml?.totalRequests !== undefined ? `${metricsData.ml.totalRequests} / ${metricsData.ml.failureCount}` : 'Unavailable'}
          </div>
          <div className="kpi-subtitle">
            Avg Latency: {metricsData?.ml?.latency?.avg !== undefined ? `${metricsData.ml.latency.avg} ms` : 'Unavailable'}
          </div>
        </div>

        <div className="soc-card kpi-card" style={{ padding: '1.1rem' }}>
          <div className="kpi-title">Sensor Packets / Flows</div>
          <div className="kpi-value">
            {metricsData?.sensor?.packetsProcessed !== undefined ? `${metricsData.sensor.packetsProcessed} / ${metricsData.sensor.flowsCreated}` : 'Unavailable'}
          </div>
          <div className="kpi-subtitle">
            Active Flows: {metricsData?.sensor?.activeFlows ?? 'Unavailable'}
          </div>
        </div>
      </div>

      {/* Operational Incidents Panel */}
      <div className="soc-card" style={{ padding: '1.25rem' }}>
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '1rem',
          marginBottom: '1rem'
        }}>
          <div>
            <h3 style={{
              fontSize: '1.05rem',
              fontWeight: 600,
              color: '#f8fafc',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              margin: 0
            }}>
              <ShieldAlert size={18} style={{ color: 'var(--accent-amber)' }} />
              Operational Incidents Log
            </h3>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', margin: '0.2rem 0 0 0' }}>
              Infrastructure and performance alert log
            </p>
          </div>

          {/* Filter Controls */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="form-select"
              style={{ fontSize: '0.8rem', padding: '0.4rem 0.75rem' }}
              aria-label="Filter incidents by severity"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="form-select"
              style={{ fontSize: '0.8rem', padding: '0.4rem 0.75rem' }}
              aria-label="Filter incidents by status"
            >
              <option value="ALL">All Statuses</option>
              <option value="OPEN">Open</option>
              <option value="ACKNOWLEDGED">Acknowledged</option>
              <option value="RESOLVED">Resolved</option>
            </select>
          </div>
        </div>

        {/* Incidents Table */}
        <div className="table-container">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Incident Type</th>
                <th>Source</th>
                <th>Message</th>
                <th>Status</th>
                <th>Last Detected</th>
                <th style={{ textAlign: 'center' }}>Occurrences</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredIncidents.length === 0 ? (
                <tr>
                  <td colSpan="8" style={{ padding: '2.5rem 1rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    No operational incidents found matching filters.
                  </td>
                </tr>
              ) : (
                filteredIncidents.map((inc) => (
                  <tr key={inc._id}>
                    <td>
                      <span className={getSeverityBadgeClass(inc.severity)}>
                        {inc.severity}
                      </span>
                    </td>
                    <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{inc.type}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--accent-cyan)' }}>{inc.source}</td>
                    <td style={{ color: 'var(--text-secondary)', maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={inc.message}>
                      {inc.message}
                    </td>
                    <td>
                      <span className="badge" style={getIncidentStatusBadgeStyle(inc.status)}>
                        {inc.status}
                      </span>
                    </td>
                    <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem', whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)' }}>
                      {new Date(inc.lastDetectedAt || inc.createdAt).toLocaleTimeString()}
                    </td>
                    <td style={{ textAlign: 'center', fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
                      {inc.occurrenceCount || 1}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      {canManageIncidents && inc.status !== 'RESOLVED' ? (
                        <div style={{ display: 'inline-flex', gap: '0.4rem', justifyContent: 'flex-end' }}>
                          {inc.status === 'OPEN' && (
                            <button
                              onClick={() => handleUpdateStatus(inc._id, 'ACKNOWLEDGED')}
                              disabled={actionLoading === inc._id}
                              className="btn"
                              style={{
                                padding: '0.25rem 0.6rem',
                                fontSize: '0.75rem',
                                background: 'rgba(245, 158, 11, 0.15)',
                                color: '#fbbf24',
                                borderColor: 'rgba(245, 158, 11, 0.3)'
                              }}
                            >
                              Ack
                            </button>
                          )}
                          <button
                            onClick={() => handleUpdateStatus(inc._id, 'RESOLVED')}
                            disabled={actionLoading === inc._id}
                            className="btn"
                            style={{
                              padding: '0.25rem 0.6rem',
                              fontSize: '0.75rem',
                              background: 'rgba(16, 185, 129, 0.15)',
                              color: '#34d399',
                              borderColor: 'rgba(16, 185, 129, 0.3)'
                            }}
                          >
                            Resolve
                          </button>
                        </div>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem', fontStyle: 'italic' }}>No action</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
