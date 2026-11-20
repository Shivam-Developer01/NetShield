import React, { useState, useEffect } from 'react';
import { BarChart3, Activity, Clock, ShieldAlert, CheckCircle, TrendingUp } from 'lucide-react';
import { getMetrics } from '../services/socService';
import LoadingSpinner from '../components/common/LoadingSpinner';
import ErrorBanner from '../components/common/ErrorBanner';

const MetricsPage = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [metrics, setMetrics] = useState(null);

  const fetchMetrics = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getMetrics();
      setMetrics(res.data);
    } catch (err) {
      setError(err.message || 'Failed to fetch system metrics.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMetrics();
  }, []);

  if (loading) return <LoadingSpinner message="Fetching system telemetry metrics..." />;
  if (error) return <ErrorBanner message={error} onRetry={fetchMetrics} title="System Metrics Error" />;

  const measured = metrics?.measured || {};
  const calculated = metrics?.calculated || {};

  return (
    <div>
      <div style={{ marginBottom: '1.5rem' }}>
        <h2 style={{ fontSize: '1.35rem', fontWeight: 700, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <BarChart3 size={22} style={{ color: 'var(--accent-cyan)' }} />
          System Telemetry & Performance Benchmarks
        </h2>
        <p style={{ fontSize: '0.825rem', color: 'var(--text-muted)', margin: '0.2rem 0 0 0' }}>
          Measured flow counts, malicious detection ratios, and Node.js → FastAPI IPC latencies
        </p>
      </div>

      <div className="soc-card" style={{ marginBottom: '1.5rem' }}>
        <h3 style={{ fontSize: '1rem', fontWeight: 600, color: '#f8fafc', marginBottom: '1rem' }}>
          Measured Telemetry Facts
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1.25rem' }}>
          <div style={{ background: '#0f172a', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Total Logged Flows</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#fff', fontFamily: 'var(--font-mono)' }}>{measured.totalFlows}</div>
            <div style={{ fontSize: '0.7rem', color: 'var(--accent-cyan)' }}>Category: Measured Fact</div>
          </div>

          <div style={{ background: '#0f172a', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Benign Flow Count</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#34d399', fontFamily: 'var(--font-mono)' }}>{measured.benignFlows}</div>
            <div style={{ fontSize: '0.7rem', color: '#34d399' }}>Category: Measured Fact</div>
          </div>

          <div style={{ background: '#0f172a', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Threat Flow Count</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f87171', fontFamily: 'var(--font-mono)' }}>{measured.maliciousFlows}</div>
            <div style={{ fontSize: '0.7rem', color: '#f87171' }}>Category: Measured Fact</div>
          </div>

          <div style={{ background: '#0f172a', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Active Queue Alerts</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#fbbf24', fontFamily: 'var(--font-mono)' }}>{measured.activeAlerts}</div>
            <div style={{ fontSize: '0.7rem', color: '#fbbf24' }}>Category: Measured Fact</div>
          </div>

          <div style={{ background: '#0f172a', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Calculated Detection Rate</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--accent-purple)', fontFamily: 'var(--font-mono)' }}>{calculated.detectionRate}%</div>
            <div style={{ fontSize: '0.7rem', color: 'var(--accent-purple)' }}>Category: Calculated Aggregate</div>
          </div>

          <div style={{ background: '#0f172a', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Avg Pipeline Latency</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>{measured.processingLatencyMs} ms</div>
            <div style={{ fontSize: '0.7rem', color: 'var(--accent-cyan)' }}>Category: Measured Fact</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default MetricsPage;
