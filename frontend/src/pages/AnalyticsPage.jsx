import React, { useState, useEffect, useCallback } from 'react';
import { 
  BarChart, Bar, LineChart, Line, AreaChart, Area, PieChart, Pie, Cell, 
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer 
} from 'recharts';
import { 
  ShieldAlert, Activity, Cpu, AlertTriangle, Download, Calendar, 
  Clock, CheckCircle, RefreshCw, Zap
} from 'lucide-react';
import { useAuth } from '../auth/AuthContext';
import { 
  getOverview, getTrends, getAttacks, getSeverity, getModels, 
  getAlertAnalytics, downloadExport 
} from '../services/analyticsService';
import LoadingSpinner from '../components/common/LoadingSpinner';
import ErrorBanner from '../components/common/ErrorBanner';
import { subscribeToEvent } from '../services/socket';

const SEVERITY_COLORS = {
  critical: '#f87171',
  high: '#fbbf24',
  medium: '#38bdf8',
  low: '#a7f3d0',
  benign: '#34d399'
};

const AnalyticsPage = ({ globalDatasetFilter }) => {
  const { role } = useAuth();
  const [datasetFilter, setDatasetFilter] = useState(globalDatasetFilter || 'all');
  const [timeRange, setTimeRange] = useState('24h');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [overview, setOverview] = useState(null);
  const [trends, setTrends] = useState([]);
  const [attacks, setAttacks] = useState([]);
  const [severityData, setSeverityData] = useState([]);
  const [modelsData, setModelsData] = useState([]);
  const [alertStats, setAlertStats] = useState(null);
  const [isExporting, setIsExporting] = useState(false);

  useEffect(() => {
    if (globalDatasetFilter) {
      setDatasetFilter(globalDatasetFilter);
    }
  }, [globalDatasetFilter]);

  const getTimeQueryParams = useCallback(() => {
    const params = {};
    if (datasetFilter !== 'all') params.datasetType = datasetFilter;

    const now = new Date();
    if (timeRange === '1h') {
      params.startDate = new Date(now.getTime() - 60 * 60 * 1000).toISOString();
      params.interval = 'hour';
    } else if (timeRange === '24h') {
      params.startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
      params.interval = 'hour';
    } else if (timeRange === '7d') {
      params.startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();
      params.interval = 'day';
    } else if (timeRange === '30d') {
      params.startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
      params.interval = 'day';
    } else {
      params.interval = 'day';
    }
    return params;
  }, [datasetFilter, timeRange]);

  const fetchAnalytics = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const query = getTimeQueryParams();

      const [overviewRes, trendsRes, attacksRes, severityRes, modelsRes, alertStatsRes] = await Promise.all([
        getOverview(query),
        getTrends(query),
        getAttacks(query),
        getSeverity(query),
        getModels(query),
        getAlertAnalytics(query)
      ]);

      setOverview(overviewRes);
      setTrends(trendsRes.data || []);
      setAttacks(attacksRes.data || []);

      const sev = severityRes.data || {};
      const sevPieData = [
        { name: 'Critical', value: sev.critical?.count || 0, color: SEVERITY_COLORS.critical },
        { name: 'High', value: sev.high?.count || 0, color: SEVERITY_COLORS.high },
        { name: 'Medium', value: sev.medium?.count || 0, color: SEVERITY_COLORS.medium },
        { name: 'Low', value: sev.low?.count || 0, color: SEVERITY_COLORS.low },
        { name: 'Benign', value: sev.benign?.count || 0, color: SEVERITY_COLORS.benign }
      ].filter(item => item.value > 0);
      setSeverityData(sevPieData);

      setModelsData(modelsRes.data || []);
      setAlertStats(alertStatsRes.data || null);
    } catch (err) {
      setError(err.message || 'Failed to load security analytics data.');
    } finally {
      setLoading(false);
    }
  }, [getTimeQueryParams]);

  useEffect(() => {
    fetchAnalytics();
  }, [fetchAnalytics]);

  // Real-Time Socket updates
  useEffect(() => {
    const sub1 = subscribeToEvent('prediction.created', () => fetchAnalytics());
    const sub2 = subscribeToEvent('alert.created', () => fetchAnalytics());
    const sub3 = subscribeToEvent('alert.updated', () => fetchAnalytics());

    return () => {
      if (typeof sub1 === 'function') sub1();
      if (typeof sub2 === 'function') sub2();
      if (typeof sub3 === 'function') sub3();
    };
  }, [fetchAnalytics]);

  const handleExport = async (type) => {
    setIsExporting(true);
    try {
      const query = getTimeQueryParams();
      query.type = type;
      await downloadExport(query);
    } catch (err) {
      alert(`Export failed: ${err.message}`);
    } finally {
      setIsExporting(false);
    }
  };

  const isExportAllowed = role === 'ADMIN' || role === 'ANALYST';

  if (loading && !overview) {
    return <LoadingSpinner message="Aggregating SOC security analytics & threat intelligence..." />;
  }

  return (
    <div className="analytics-page" style={{ padding: '1.5rem 0' }}>
      {/* Top Filter Bar */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '1rem',
        marginBottom: '1.5rem',
        background: 'rgba(30, 41, 59, 0.5)',
        padding: '1rem 1.25rem',
        borderRadius: '12px',
        border: '1px solid var(--border-color)'
      }}>
        <div>
          <h1 style={{ fontSize: '1.4rem', fontWeight: 800, color: '#f8fafc', margin: 0, display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <Activity style={{ color: 'var(--accent-cyan)' }} size={24} />
            Advanced Security Analytics & Threat Intelligence
          </h1>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: '0.2rem 0 0 0' }}>
            Historical trends, attack distributions, model benchmarks, and alert telemetry
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          {/* Time Range Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <Clock size={14} style={{ color: 'var(--text-muted)' }} />
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="form-select"
              style={{ fontSize: '0.8rem', padding: '0.4rem 0.75rem' }}
            >
              <option value="1h">Last 1 Hour</option>
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
              <option value="all">All Time</option>
            </select>
          </div>

          {/* Dataset Filter */}
          <select
            value={datasetFilter}
            onChange={(e) => setDatasetFilter(e.target.value)}
            className="form-select"
            style={{ fontSize: '0.8rem', padding: '0.4rem 0.75rem' }}
          >
            <option value="all">All Datasets</option>
            <option value="nsl_kdd">NSL-KDD Benchmark</option>
            <option value="cicids2017">CICIDS2017 Flow</option>
          </select>

          <button onClick={fetchAnalytics} className="btn" style={{ padding: '0.4rem 0.75rem', fontSize: '0.8rem' }} title="Refresh Analytics">
            <RefreshCw size={14} />
          </button>

          {/* Export Controls */}
          {isExportAllowed && (
            <div style={{ display: 'flex', gap: '0.35rem' }}>
              <button 
                onClick={() => handleExport('analytics')} 
                disabled={isExporting} 
                className="btn btn-primary"
                style={{ padding: '0.4rem 0.75rem', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
              >
                <Download size={14} />
                Export CSV
              </button>
            </div>
          )}
        </div>
      </div>

      {error && <ErrorBanner message={error} onRetry={fetchAnalytics} />}

      {/* KPI Summary Cards Grid */}
      <div className="stats-grid" style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
        gap: '1rem',
        marginBottom: '1.75rem'
      }}>
        <div className="stat-card" style={{ background: 'rgba(30, 41, 59, 0.6)', padding: '1.1rem', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Total Predictions</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#f8fafc', marginTop: '0.3rem' }}>{overview?.totalPredictions || 0}</div>
          <div style={{ fontSize: '0.7rem', color: '#34d399', marginTop: '0.2rem' }}>{overview?.benignPredictions || 0} Benign</div>
        </div>

        <div className="stat-card" style={{ background: 'rgba(30, 41, 59, 0.6)', padding: '1.1rem', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Malicious Traffic</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#f87171', marginTop: '0.3rem' }}>{overview?.maliciousPredictions || 0}</div>
          <div style={{ fontSize: '0.7rem', color: '#f87171', marginTop: '0.2rem' }}>Detection Rate: {overview?.detectionRate || 0}%</div>
        </div>

        <div className="stat-card" style={{ background: 'rgba(30, 41, 59, 0.6)', padding: '1.1rem', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Active Alerts</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#fbbf24', marginTop: '0.3rem' }}>{overview?.activeAlerts || 0}</div>
          <div style={{ fontSize: '0.7rem', color: '#f87171', marginTop: '0.2rem' }}>{overview?.criticalAlerts || 0} Critical</div>
        </div>

        <div className="stat-card" style={{ background: 'rgba(30, 41, 59, 0.6)', padding: '1.1rem', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Avg Model Confidence</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#38bdf8', marginTop: '0.3rem' }}>{overview?.averageConfidence ? `${(overview.averageConfidence * 100).toFixed(1)}%` : 'N/A'}</div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>XGBoost Ensemble</div>
        </div>

        <div className="stat-card" style={{ background: 'rgba(30, 41, 59, 0.6)', padding: '1.1rem', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Avg ML Latency</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#a7f3d0', marginTop: '0.3rem' }}>{overview?.averageProcessingLatencyMs || 0} ms</div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>FastAPI Inference</div>
        </div>

        <div className="stat-card" style={{ background: 'rgba(30, 41, 59, 0.6)', padding: '1.1rem', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Top Attack Type</div>
          <div style={{ fontSize: '1.25rem', fontWeight: 800, color: '#f8fafc', marginTop: '0.3rem', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {overview?.topAttackType || 'None'}
          </div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>{overview?.recentThreatCount || 0} in 24h</div>
        </div>
      </div>

      {/* Visualizations Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(450px, 1fr))', gap: '1.5rem', marginBottom: '1.75rem' }}>
        {/* Threat Trend Area Chart */}
        <div style={{ background: 'rgba(30, 41, 59, 0.5)', padding: '1.25rem', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Activity size={18} style={{ color: 'var(--accent-cyan)' }} />
            Threat Activity Trend ({timeRange.toUpperCase()})
          </h3>
          <div style={{ width: '100%', height: 260 }}>
            {trends.length > 0 ? (
              <ResponsiveContainer>
                <AreaChart data={trends} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
                  <XAxis dataKey="timestamp" stroke="var(--text-muted)" fontSize={11} />
                  <YAxis stroke="var(--text-muted)" fontSize={11} />
                  <Tooltip 
                    contentStyle={{ background: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#ffffff' }}
                    itemStyle={{ color: '#ffffff' }}
                    labelStyle={{ color: '#ffffff' }}
                  />
                  <Legend />
                  <Area type="monotone" dataKey="total" name="Total Flows" stroke="#38bdf8" fill="rgba(56, 189, 248, 0.15)" />
                  <Area type="monotone" dataKey="malicious" name="Malicious" stroke="#f87171" fill="rgba(248, 113, 113, 0.2)" />
                  <Area type="monotone" dataKey="alerts" name="Alerts Generated" stroke="#fbbf24" fill="rgba(251, 191, 36, 0.2)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ display: 'flex', height: '100%', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>No trend data recorded for selected period.</div>
            )}
          </div>
        </div>

        {/* Attack Type Distribution Bar Chart */}
        <div style={{ background: 'rgba(30, 41, 59, 0.5)', padding: '1.25rem', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <ShieldAlert size={18} style={{ color: '#f87171' }} />
            Top Attack Categories Distribution
          </h3>
          <div style={{ width: '100%', height: 260 }}>
            {attacks.length > 0 ? (
              <ResponsiveContainer>
                <BarChart data={attacks.slice(0, 7)} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
                  <XAxis dataKey="attackType" stroke="var(--text-muted)" fontSize={10} />
                  <YAxis stroke="var(--text-muted)" fontSize={11} />
                  <Tooltip 
                    contentStyle={{ background: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#ffffff' }}
                    itemStyle={{ color: '#ffffff' }}
                    labelStyle={{ color: '#ffffff' }}
                  />
                  <Bar dataKey="count" name="Attack Count" fill="#f87171" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ display: 'flex', height: '100%', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>No malicious attack categories detected.</div>
            )}
          </div>
        </div>
      </div>

      {/* Second Row: Severity Donut Chart & Model Performance Table */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(450px, 1fr))', gap: '1.5rem' }}>
        {/* Severity Distribution Pie/Donut */}
        <div style={{ background: 'rgba(30, 41, 59, 0.5)', padding: '1.25rem', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <AlertTriangle size={18} style={{ color: '#fbbf24' }} />
            Threat Severity Distribution
          </h3>
          <div style={{ width: '100%', height: 250, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            {severityData.length > 0 ? (
              <ResponsiveContainer>
                <PieChart>
                  <Pie data={severityData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={55} outerRadius={85} paddingAngle={4}>
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ background: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#ffffff' }}
                    itemStyle={{ color: '#ffffff' }}
                    labelStyle={{ color: '#ffffff' }}
                  />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ color: 'var(--text-muted)' }}>No threat severity telemetry.</div>
            )}
          </div>
        </div>

        {/* Model Performance Comparison Table */}
        <div style={{ background: 'rgba(30, 41, 59, 0.5)', padding: '1.25rem', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Cpu size={18} style={{ color: 'var(--accent-cyan)' }} />
            Production Model Benchmarks
          </h3>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', textAlign: 'left' }}>
                <th style={{ padding: '0.5rem' }}>Dataset</th>
                <th style={{ padding: '0.5rem' }}>Flows</th>
                <th style={{ padding: '0.5rem' }}>Detection %</th>
                <th style={{ padding: '0.5rem' }}>Avg Conf.</th>
                <th style={{ padding: '0.5rem' }}>Latency</th>
              </tr>
            </thead>
            <tbody>
              {modelsData.map((m) => (
                <tr key={m.datasetType} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                  <td style={{ padding: '0.65rem 0.5rem', fontWeight: 700, color: '#f8fafc' }}>
                    {m.datasetType === 'nsl_kdd' ? 'NSL-KDD Benchmark' : 'CICIDS2017 Network Flow'}
                  </td>
                  <td style={{ padding: '0.65rem 0.5rem', color: 'var(--text-muted)' }}>{m.predictionCount}</td>
                  <td style={{ padding: '0.65rem 0.5rem', color: m.detectionRate > 0 ? '#f87171' : '#34d399', fontWeight: 600 }}>
                    {m.detectionRate}%
                  </td>
                  <td style={{ padding: '0.65rem 0.5rem', color: '#38bdf8' }}>
                    {m.averageConfidence ? `${(m.averageConfidence * 100).toFixed(1)}%` : 'N/A'}
                  </td>
                  <td style={{ padding: '0.65rem 0.5rem', color: '#a7f3d0' }}>
                    {m.averageLatency} ms
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {alertStats && (
            <div style={{ marginTop: '1.25rem', paddingTop: '1rem', borderTop: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              <div>
                Avg Ack Time:{' '}
                <strong style={{ color: '#f8fafc' }}>
                  {alertStats.averageTimeToAckMs !== null 
                    ? `${(alertStats.averageTimeToAckMs / 1000).toFixed(1)}s` 
                    : 'N/A — No acknowledged alerts'}
                </strong>
              </div>
              <div>
                Avg Resolve Time:{' '}
                <strong style={{ color: '#f8fafc' }}>
                  {alertStats.averageTimeToResolutionMs !== null 
                    ? `${(alertStats.averageTimeToResolutionMs / 1000).toFixed(1)}s` 
                    : 'N/A — No resolved alerts'}
                </strong>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AnalyticsPage;
