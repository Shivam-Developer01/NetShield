import React, { useState, useEffect } from 'react';
import { 
  Activity, 
  ShieldAlert, 
  CheckCircle, 
  AlertTriangle, 
  Clock, 
  Zap, 
  Cpu, 
  Layers,
  TrendingUp,
  ArrowRight
} from 'lucide-react';
import { 
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend,
  BarChart, Bar, XAxis, YAxis, CartesianGrid
} from 'recharts';
import { Link } from 'react-router-dom';
import { getMetrics, getPredictions, getAlerts, updateAlertStatus, getModelInfo } from '../services/socService';
import LoadingSpinner from '../components/common/LoadingSpinner';
import ErrorBanner from '../components/common/ErrorBanner';
import SeverityBadge from '../components/common/SeverityBadge';

import { useAuth } from '../auth/AuthContext';

const COLORS = {
  benign: '#10b981',
  malicious: '#f43f5e',
  low: '#3b82f6',
  medium: '#f59e0b',
  high: '#f97316',
  critical: '#f43f5e'
};

const DashboardPage = ({ datasetFilter, onDataRefreshed }) => {
  const { role } = useAuth();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [metrics, setMetrics] = useState(null);
  const [modelInfo, setModelInfo] = useState(null);
  const [recentPredictions, setRecentPredictions] = useState([]);
  const [activeAlerts, setActiveAlerts] = useState([]);

  const fetchData = async (currentFilter = datasetFilter) => {
    setLoading(true);
    setError(null);
    try {
      const [metricsRes, predRes, alertRes, modelInfoRes] = await Promise.all([
        getMetrics({ datasetType: currentFilter }),
        getPredictions({ limit: 5, datasetType: currentFilter }),
        getAlerts({ limit: 5, status: 'open', datasetType: currentFilter }),
        getModelInfo().catch(() => ({ data: null }))
      ]);

      setMetrics(metricsRes.data);
      setRecentPredictions(predRes.data || []);
      setActiveAlerts(alertRes.data || []);
      if (modelInfoRes?.data?.models) {
        setModelInfo(modelInfoRes.data.models);
      }
      if (onDataRefreshed) onDataRefreshed();
    } catch (err) {
      setError(err.message || 'Failed to connect to NetShield backend service.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let cancelled = false;

    const loadData = async () => {
      setLoading(true);
      setError(null);
      try {
        const [metricsRes, predRes, alertRes, modelInfoRes] = await Promise.all([
          getMetrics({ datasetType: datasetFilter }),
          getPredictions({ limit: 5, datasetType: datasetFilter }),
          getAlerts({ limit: 5, status: 'open', datasetType: datasetFilter }),
          getModelInfo().catch(() => ({ data: null }))
        ]);

        if (!cancelled) {
          setMetrics(metricsRes.data);
          setRecentPredictions(predRes.data || []);
          setActiveAlerts(alertRes.data || []);
          if (modelInfoRes?.data?.models) {
            setModelInfo(modelInfoRes.data.models);
          }
          if (onDataRefreshed) onDataRefreshed();
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || 'Failed to connect to NetShield backend service.');
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    loadData();

    return () => {
      cancelled = true;
    };
  }, [datasetFilter]);

  const handleUpdateStatus = async (id, newStatus) => {
    try {
      await updateAlertStatus(id, newStatus);
      fetchData();
    } catch (err) {
      alert(`Failed to update alert status: ${err.message}`);
    }
  };

  if (loading) return <LoadingSpinner message="Fetching live SOC telemetry & threat statistics..." />;
  if (error) return <ErrorBanner message={error} onRetry={() => fetchData(datasetFilter)} title="SOC Data Feed Error" />;

  const measured = metrics?.measured || { totalFlows: 0, benignFlows: 0, maliciousFlows: 0, activeAlerts: 0, processingLatencyMs: 0 };
  const calculated = metrics?.calculated || { detectionRate: 0 };
  const scopeLabel = datasetFilter === 'cicids2017'
    ? 'CICIDS2017'
    : datasetFilter === 'nsl_kdd'
      ? 'NSL-KDD'
      : 'All Datasets';

  // Prepare chart datasets
  const trafficPieData = [
    { name: 'Benign Traffic', value: measured.benignFlows || 0, color: COLORS.benign },
    { name: 'Threat Flows', value: measured.maliciousFlows || 0, color: COLORS.malicious }
  ];

  // Aggregate recent attack distribution from predictions
  const attackCounts = {};
  recentPredictions.forEach(p => {
    if (p.prediction !== 'Normal' && p.prediction !== 'BENIGN') {
      attackCounts[p.prediction] = (attackCounts[p.prediction] || 0) + 1;
    }
  });

  const attackBarData = Object.keys(attackCounts).map(k => ({
    attack: k,
    count: attackCounts[k]
  }));

  return (
    <div>
      {/* KPI Cards Grid */}
      <div className="kpi-grid">
        <div className="soc-card kpi-card">
          <div className="kpi-title">
            <Activity size={16} style={{ color: 'var(--accent-cyan)' }} />
            Total Flow Volume
          </div>
          <div className="kpi-value">{measured.totalFlows.toLocaleString()}</div>
          <div className="kpi-subtitle">Ingested {scopeLabel} traffic records</div>
        </div>

        <div className="soc-card kpi-card">
          <div className="kpi-title">
            <CheckCircle size={16} style={{ color: 'var(--accent-emerald)' }} />
            Benign Flows
          </div>
          <div className="kpi-value" style={{ color: '#34d399' }}>{measured.benignFlows.toLocaleString()}</div>
          <div className="kpi-subtitle">Verified clean {scopeLabel} traffic</div>
        </div>

        <div className="soc-card kpi-card">
          <div className="kpi-title">
            <AlertTriangle size={16} style={{ color: 'var(--accent-rose)' }} />
            Malicious Threats
          </div>
          <div className="kpi-value" style={{ color: '#f87171' }}>{measured.maliciousFlows.toLocaleString()}</div>
          <div className="kpi-subtitle">Detected {scopeLabel} intrusion attacks</div>
        </div>

        <div className="soc-card kpi-card">
          <div className="kpi-title">
            <TrendingUp size={16} style={{ color: 'var(--accent-purple)' }} />
            Detection Rate
          </div>
          <div className="kpi-value">{calculated.detectionRate}%</div>
          <div className="kpi-subtitle">Ratio of {scopeLabel} threat flows / total</div>
        </div>

        <div className="soc-card kpi-card">
          <div className="kpi-title">
            <ShieldAlert size={16} style={{ color: 'var(--accent-amber)' }} />
            Active Alerts
          </div>
          <div className="kpi-value" style={{ color: '#fbbf24' }}>{measured.activeAlerts}</div>
          <div className="kpi-subtitle">Open alerts in queue ({scopeLabel})</div>
        </div>

        <div className="soc-card kpi-card">
          <div className="kpi-title">
            <Clock size={16} style={{ color: 'var(--accent-cyan)' }} />
            Avg IPC Latency
          </div>
          <div className="kpi-value">{measured.processingLatencyMs} ms</div>
          <div className="kpi-subtitle">Node.js → FastAPI pipeline speed ({scopeLabel})</div>
        </div>
      </div>

      {/* Visual Charts Grid */}
      <div className="charts-grid">
        {/* Traffic Ratio Pie Chart */}
        <div className="soc-card">
          <h3 style={{ fontSize: '1rem', fontWeight: 600, color: '#f8fafc', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Zap size={16} style={{ color: 'var(--accent-cyan)' }} />
            Traffic Ratio Classification
          </h3>
          {measured.totalFlows === 0 ? (
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', textAlign: 'center', padding: '3rem 0' }}>
              No prediction records recorded yet. Submit predictions to populate charts.
            </p>
          ) : (
            <div style={{ width: '100%', height: 260 }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={trafficPieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={90}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {trafficPieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ background: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#ffffff' }}
                    itemStyle={{ color: '#ffffff' }}
                    labelStyle={{ color: '#ffffff' }}
                  />
                  <Legend verticalAlign="bottom" height={36} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Attack Category Breakdown Bar Chart */}
        <div className="soc-card">
          <h3 style={{ fontSize: '1rem', fontWeight: 600, color: '#f8fafc', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Layers size={16} style={{ color: 'var(--accent-rose)' }} />
            Recent Attack Category Distribution
          </h3>
          {attackBarData.length === 0 ? (
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', textAlign: 'center', padding: '3rem 0' }}>
              No threat detections in recent sample feed.
            </p>
          ) : (
            <div style={{ width: '100%', height: 260 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={attackBarData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="attack" stroke="#94a3b8" fontSize={12} />
                  <YAxis stroke="#94a3b8" fontSize={12} allowDecimals={false} />
                  <Tooltip 
                    contentStyle={{ background: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#ffffff' }}
                    itemStyle={{ color: '#ffffff' }}
                    labelStyle={{ color: '#ffffff' }}
                  />
                  <Bar dataKey="count" fill="#f43f5e" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      {/* Production Models Info Section */}
      <div className="soc-card" style={{ marginBottom: '1.75rem' }}>
        <h3 style={{ fontSize: '1rem', fontWeight: 600, color: '#f8fafc', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Cpu size={18} style={{ color: 'var(--accent-cyan)' }} />
          Active Production ML Engine Models
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1rem' }}>
          <div style={{ background: '#0f172a', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
              <span style={{ fontWeight: 700, color: 'var(--accent-cyan)', fontSize: '0.9rem' }}>NSL-KDD Model</span>
              <span className="badge badge-benign">{modelInfo?.nsl_kdd?.status || 'Active'}</span>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', margin: 0 }}>
              Version: <code>{modelInfo?.nsl_kdd?.model_version || 'NetShield-NSLKDD-ExpertEnsemble-v1.3'}</code>
            </p>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', margin: '0.2rem 0' }}>
              Features: {modelInfo?.nsl_kdd?.feature_count || 134} selected columns | Algorithm: {modelInfo?.nsl_kdd?.algorithm || 'Multi-Model Expert Ensemble (Base + Specialists)'}
            </p>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: 0 }}>
              Accuracy: {modelInfo?.nsl_kdd?.accuracy ? (modelInfo.nsl_kdd.accuracy * 100).toFixed(2) : '81.23'}% | Empirical Weighted F1: {modelInfo?.nsl_kdd?.weighted_f1 ? modelInfo.nsl_kdd.weighted_f1.toFixed(4) : '0.7995'}
            </p>
            <p style={{ fontSize: '0.72rem', color: '#64748b', margin: '0.35rem 0 0 0' }}>
              Provenance: {modelInfo?.nsl_kdd?.provenance || 'Multi-Model Expert Ensemble (Frozen v1.3)'}
            </p>
          </div>

          <div style={{ background: '#0f172a', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
              <span style={{ fontWeight: 700, color: 'var(--accent-cyan)', fontSize: '0.9rem' }}>CICIDS2017 Model</span>
              <span className="badge badge-benign">{modelInfo?.cicids2017?.status || 'Active'}</span>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', margin: 0 }}>
              Version: <code>{modelInfo?.cicids2017?.model_version || 'NetShield-CICIDS2017-TwoStage-v1.2'}</code>
            </p>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', margin: '0.2rem 0' }}>
              Features: {modelInfo?.cicids2017?.feature_count || 56} selected columns | Algorithm: {modelInfo?.cicids2017?.algorithm || 'Two-Stage Cascade (Hist XGBoost)'}
            </p>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: 0 }}>
              Accuracy: {modelInfo?.cicids2017?.accuracy ? (modelInfo.cicids2017.accuracy * 100).toFixed(2) : '99.25'}% | Empirical Weighted F1: {modelInfo?.cicids2017?.weighted_f1 ? modelInfo.cicids2017.weighted_f1.toFixed(4) : '0.9930'}
            </p>
            <p style={{ fontSize: '0.72rem', color: '#64748b', margin: '0.35rem 0 0 0' }}>
              Provenance: {modelInfo?.cicids2017?.provenance || 'Two-Stage Cascade Holdout (Frozen v1.2)'}
            </p>
          </div>
        </div>
      </div>

      {/* Tables Row: Recent Predictions & Open Alerts */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(480px, 1fr))', gap: '1.5rem' }}>
        {/* Active Open Alerts Preview */}
        <div className="soc-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 600, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <ShieldAlert size={16} style={{ color: 'var(--accent-rose)' }} />
              Active Open Security Alerts
            </h3>
            <Link to="/alerts" style={{ fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
              View All <ArrowRight size={12} />
            </Link>
          </div>

          {activeAlerts.length === 0 ? (
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', padding: '1.5rem 0', textAlign: 'center' }}>
              No open security alerts in queue.
            </p>
          ) : (
            <div className="table-container">
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Severity</th>
                    <th>Attack Type</th>
                    <th>Dataset</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {activeAlerts.map(alert => (
                    <tr key={alert._id}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </td>
                      <td><SeverityBadge severity={alert.severity} /></td>
                      <td style={{ fontWeight: 600 }}>{alert.attackType}</td>
                      <td style={{ textTransform: 'uppercase', fontSize: '0.75rem' }}>{alert.datasetType}</td>
                      <td>
                        {role === 'VIEWER' ? (
                          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Read Only</span>
                        ) : (
                          <button 
                            onClick={() => handleUpdateStatus(alert._id, 'acknowledged')}
                            className="btn"
                            style={{ padding: '0.25rem 0.5rem', fontSize: '0.7rem' }}
                          >
                            Ack
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Recent Prediction Logs Preview */}
        <div className="soc-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 600, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Activity size={16} style={{ color: 'var(--accent-cyan)' }} />
              Recent Prediction Feed
            </h3>
            <Link to="/threats" style={{ fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
              View All <ArrowRight size={12} />
            </Link>
          </div>

          {recentPredictions.length === 0 ? (
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', padding: '1.5rem 0', textAlign: 'center' }}>
              No prediction logs recorded yet.
            </p>
          ) : (
            <div className="table-container">
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Dataset</th>
                    <th>Prediction</th>
                    <th>Confidence</th>
                    <th>Latency</th>
                  </tr>
                </thead>
                <tbody>
                  {recentPredictions.map(log => (
                    <tr key={log._id}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </td>
                      <td style={{ textTransform: 'uppercase', fontSize: '0.75rem' }}>{log.datasetType}</td>
                      <td>
                        <SeverityBadge 
                          prediction={log.prediction}
                          isBenign={log.prediction === 'Normal' || log.prediction === 'BENIGN'} 
                        />
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                        {(log.confidence * 100).toFixed(1)}%
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {log.processingLatencyMs}ms
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default DashboardPage;
