import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
  ArrowLeft, ShieldAlert, CheckCircle, Clock, Cpu, Database, 
  Activity, AlertTriangle, UserCheck, Layers
} from 'lucide-react';
import { getInvestigation, getRelatedActivity } from '../services/analyticsService';
import LoadingSpinner from '../components/common/LoadingSpinner';
import ErrorBanner from '../components/common/ErrorBanner';
import SeverityBadge from '../components/common/SeverityBadge';

const AlertInvestigationPage = () => {
  const { id } = useParams();
  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [investigation, setInvestigation] = useState(null);
  const [activity, setActivity] = useState(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [invRes, actRes] = await Promise.all([
        getInvestigation(id),
        getRelatedActivity(id, 15)
      ]);

      setInvestigation(invRes.data);
      setActivity(actRes.data);
    } catch (err) {
      setError(err.message || 'Failed to load alert investigation details.');
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  if (loading) {
    return <LoadingSpinner message="Correlating threat events and building investigation timeline..." />;
  }

  if (error || !investigation) {
    return (
      <div style={{ padding: '2rem 0' }}>
        <button onClick={() => navigate('/alerts')} className="btn" style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <ArrowLeft size={16} /> Back to Alerts
        </button>
        <ErrorBanner message={error || 'Alert not found.'} onRetry={fetchData} />
      </div>
    );
  }

  const { alert, relatedLog, timeline } = investigation;

  return (
    <div className="alert-investigation-page" style={{ padding: '1.5rem 0' }}>
      {/* Navigation & Header Bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
        <button 
          onClick={() => navigate('/alerts')} 
          className="btn" 
          style={{ padding: '0.45rem 0.85rem', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
        >
          <ArrowLeft size={16} /> Back to Alerts
        </button>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <SeverityBadge severity={alert.severity} />
          <span className="badge" style={{
            background: alert.status === 'resolved' ? 'rgba(16, 185, 129, 0.15)' : alert.status === 'acknowledged' ? 'rgba(245, 158, 11, 0.15)' : 'rgba(244, 63, 94, 0.15)',
            color: alert.status === 'resolved' ? '#34d399' : alert.status === 'acknowledged' ? '#fbbf24' : '#f87171',
            border: '1px solid rgba(255,255,255,0.1)',
            textTransform: 'uppercase',
            fontSize: '0.75rem',
            padding: '0.25rem 0.65rem'
          }}>
            STATUS: {alert.status}
          </span>
        </div>
      </div>

      {/* Main Alert Investigation Title Card */}
      <div style={{
        background: 'rgba(30, 41, 59, 0.6)',
        borderLeft: `4px solid ${alert.severity === 'critical' ? '#f87171' : alert.severity === 'high' ? '#fbbf24' : '#38bdf8'}`,
        borderTop: '1px solid var(--border-color)',
        borderRight: '1px solid var(--border-color)',
        borderBottom: '1px solid var(--border-color)',
        borderRadius: '12px',
        padding: '1.5rem',
        marginBottom: '1.75rem'
      }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>
              SOC Security Investigation #{alert.id}
            </span>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#f8fafc', margin: '0.25rem 0 0.5rem 0' }}>
              Threat Attack: {alert.attackType} ({alert.prediction})
            </h1>
            <p style={{ fontSize: '0.9rem', color: 'var(--text-muted)', margin: 0, lineHeight: 1.4 }}>
              {alert.description}
            </p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.3rem' }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Dataset Benchmark</div>
            <div className="badge" style={{ background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8', fontSize: '0.8rem', fontWeight: 700 }}>
              {alert.datasetType === 'nsl_kdd' ? 'NSL-KDD' : 'CICIDS2017'}
            </div>
          </div>
        </div>
      </div>

      {/* Two Column Layout: Details Card + Lifecycle Timeline */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '1.5rem', marginBottom: '1.75rem' }}>
        {/* Threat Telemetry & Model Metadata Card */}
        <div style={{ background: 'rgba(30, 41, 59, 0.5)', padding: '1.25rem', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
          <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#f8fafc', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Cpu size={18} style={{ color: 'var(--accent-cyan)' }} />
            Inference Metadata & Model Telemetry
          </h3>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', fontSize: '0.85rem' }}>
            <div>
              <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>Prediction Classification</div>
              <div style={{ fontWeight: 700, color: '#f87171', fontSize: '1rem', marginTop: '0.2rem' }}>{alert.prediction}</div>
            </div>

            <div>
              <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>Model Confidence</div>
              <div style={{ fontWeight: 700, color: '#38bdf8', fontSize: '1rem', marginTop: '0.2rem' }}>
                {(alert.confidence * 100).toFixed(1)}%
              </div>
            </div>

            <div>
              <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>FastAPI Processing Latency</div>
              <div style={{ fontWeight: 600, color: '#a7f3d0', marginTop: '0.2rem' }}>
                {relatedLog ? `${relatedLog.processingLatencyMs} ms` : 'N/A'}
              </div>
            </div>

            <div>
              <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>Authoritative Model Version</div>
              <div style={{ fontWeight: 600, color: '#f8fafc', marginTop: '0.2rem', fontSize: '0.75rem' }}>
                {alert.modelVersion}
              </div>
            </div>

            <div>
              <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>Alert Triggered At</div>
              <div style={{ fontWeight: 600, color: 'var(--text-muted)', marginTop: '0.2rem', fontSize: '0.75rem' }}>
                {new Date(alert.timestamp).toLocaleString()}
              </div>
            </div>

            <div>
              <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>Acknowledged At</div>
              <div style={{ fontWeight: 600, color: alert.acknowledgedAt ? '#fbbf24' : 'var(--text-muted)', marginTop: '0.2rem', fontSize: '0.75rem' }}>
                {alert.acknowledgedAt ? new Date(alert.acknowledgedAt).toLocaleString() : 'Not Acknowledged'}
              </div>
            </div>
          </div>
        </div>

        {/* Interactive Event Lifecycle Timeline */}
        <div style={{ background: 'rgba(30, 41, 59, 0.5)', padding: '1.25rem', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
          <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#f8fafc', marginBottom: '1.25rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Layers size={18} style={{ color: '#fbbf24' }} />
            Threat Lifecycle & Investigation Timeline
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', position: 'relative', paddingLeft: '0.5rem' }}>
            {timeline.map((step, idx) => (
              <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem', position: 'relative' }}>
                <div style={{
                  width: '28px',
                  height: '28px',
                  borderRadius: '50%',
                  background: step.stage === 'ALERT_CREATED' ? 'rgba(248, 113, 113, 0.2)' : 'rgba(56, 189, 248, 0.2)',
                  border: `2px solid ${step.stage === 'ALERT_CREATED' ? '#f87171' : '#38bdf8'}`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#f8fafc',
                  flexShrink: 0
                }}>
                  <Clock size={14} />
                </div>

                <div style={{ flex: 1, background: 'rgba(15, 23, 42, 0.4)', padding: '0.75rem 1rem', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.05)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.2rem' }}>
                    <span style={{ fontSize: '0.85rem', fontWeight: 700, color: '#f8fafc' }}>{step.label}</span>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                      {new Date(step.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    Stage: <code style={{ color: 'var(--accent-cyan)' }}>{step.stage}</code>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Related Network Activity Feed (Bounded ±15 min) */}
      <div style={{ background: 'rgba(30, 41, 59, 0.5)', padding: '1.25rem', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
        <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#f8fafc', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Activity size={18} style={{ color: '#34d399' }} />
          Surrounding Network Activity (±{activity?.timeWindowMinutes || 15} Minutes Bounded Window)
        </h3>

        {activity && activity.logs && activity.logs.length > 0 ? (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', textAlign: 'left' }}>
                  <th style={{ padding: '0.5rem' }}>Timestamp</th>
                  <th style={{ padding: '0.5rem' }}>Prediction</th>
                  <th style={{ padding: '0.5rem' }}>Confidence</th>
                  <th style={{ padding: '0.5rem' }}>Dataset</th>
                  <th style={{ padding: '0.5rem' }}>Latency</th>
                </tr>
              </thead>
              <tbody>
                {activity.logs.map((log) => (
                  <tr key={log.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                    <td style={{ padding: '0.5rem', color: 'var(--text-muted)' }}>{new Date(log.timestamp).toLocaleTimeString()}</td>
                    <td style={{ padding: '0.5rem', fontWeight: 600, color: log.prediction === 'Normal' ? '#34d399' : '#f87171' }}>
                      {log.prediction}
                    </td>
                    <td style={{ padding: '0.5rem', color: '#38bdf8' }}>{(log.confidence * 100).toFixed(1)}%</td>
                    <td style={{ padding: '0.5rem', color: 'var(--text-muted)' }}>{log.datasetType}</td>
                    <td style={{ padding: '0.5rem', color: '#a7f3d0' }}>{log.processingLatencyMs} ms</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No surrounding network activity logs found within window.</div>
        )}
      </div>
    </div>
  );
};

export default AlertInvestigationPage;
