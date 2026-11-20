import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert, Filter, ChevronLeft, ChevronRight, CheckCircle2, Eye, Clock, Search } from 'lucide-react';
import { getAlerts, updateAlertStatus } from '../services/socService';
import LoadingSpinner from '../components/common/LoadingSpinner';
import ErrorBanner from '../components/common/ErrorBanner';
import SeverityBadge from '../components/common/SeverityBadge';
import { useAuth } from '../auth/AuthContext';

const AlertsPage = ({ globalDatasetFilter }) => {
  const { role } = useAuth();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [pagination, setPagination] = useState({ page: 1, limit: 20, total: 0, totalPages: 1 });

  // Filters
  const [datasetFilter, setDatasetFilter] = useState(globalDatasetFilter || 'all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [actionLoadingId, setActionLoadingId] = useState(null);

  useEffect(() => {
    setDatasetFilter(globalDatasetFilter);
  }, [globalDatasetFilter]);

  const fetchAlerts = async (pageNumber = 1) => {
    setLoading(true);
    setError(null);
    try {
      const res = await getAlerts({
        page: pageNumber,
        limit: 20,
        datasetType: datasetFilter,
        status: statusFilter,
        severity: severityFilter
      });
      setAlerts(res.data || []);
      if (res.pagination) {
        setPagination(res.pagination);
      }
    } catch (err) {
      setError(err.message || 'Failed to fetch threat alerts.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts(1);
  }, [datasetFilter, statusFilter, severityFilter]);

  const handleUpdateStatus = async (alertId, newStatus) => {
    setActionLoadingId(alertId);
    try {
      await updateAlertStatus(alertId, newStatus);
      await fetchAlerts(pagination.page);
    } catch (err) {
      alert(`Failed to update alert status: ${err.message}`);
    } finally {
      setActionLoadingId(null);
    }
  };

  const handlePageChange = (newPage) => {
    if (newPage >= 1 && newPage <= pagination.totalPages) {
      fetchAlerts(newPage);
    }
  };

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.35rem', fontWeight: 700, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <ShieldAlert size={22} style={{ color: 'var(--accent-rose)' }} />
            Security Threat Alerts
          </h2>
          <p style={{ fontSize: '0.825rem', color: 'var(--text-muted)', margin: '0.2rem 0 0 0' }}>
            Manage threat alert lifecycle status (Open → Acknowledged → Resolved)
          </p>
        </div>

        {/* Filter Controls */}
        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <Filter size={14} style={{ color: 'var(--text-muted)' }} />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="form-select"
              style={{ padding: '0.4rem 0.75rem', fontSize: '0.8rem' }}
            >
              <option value="all">All Statuses</option>
              <option value="open">Open</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="resolved">Resolved</option>
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="form-select"
              style={{ padding: '0.4rem 0.75rem', fontSize: '0.8rem' }}
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <select
              value={datasetFilter}
              onChange={(e) => setDatasetFilter(e.target.value)}
              className="form-select"
              style={{ padding: '0.4rem 0.75rem', fontSize: '0.8rem' }}
            >
              <option value="all">All Datasets</option>
              <option value="nsl_kdd">NSL-KDD</option>
              <option value="cicids2017">CICIDS2017</option>
            </select>
          </div>
        </div>
      </div>

      {error && <ErrorBanner message={error} onRetry={() => fetchAlerts(pagination.page)} />}

      {/* Alerts Table Card */}
      <div className="soc-card">
        {loading ? (
          <LoadingSpinner message="Loading threat alert queue..." />
        ) : alerts.length === 0 ? (
          <div style={{ padding: '3rem 1.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
            <ShieldAlert size={36} style={{ color: 'var(--border-color)', marginBottom: '0.75rem' }} />
            <p style={{ fontSize: '0.95rem', fontWeight: 500 }}>No security alerts match the selected criteria.</p>
          </div>
        ) : (
          <>
            <div className="table-container">
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Severity</th>
                    <th>Attack Category</th>
                    <th>Confidence</th>
                    <th>Dataset</th>
                    <th>Status</th>
                    <th>Description</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.map((alertItem) => (
                    <tr key={alertItem._id}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
                        {new Date(alertItem.timestamp).toLocaleString()}
                      </td>
                      <td><SeverityBadge severity={alertItem.severity} /></td>
                      <td style={{ fontWeight: 700, color: '#f8fafc' }}>{alertItem.attackType}</td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                        {(alertItem.confidence * 100).toFixed(1)}%
                      </td>
                      <td style={{ textTransform: 'uppercase', fontSize: '0.75rem', color: 'var(--accent-cyan)' }}>
                        {alertItem.datasetType}
                      </td>
                      <td>
                        <span className={`badge ${
                          alertItem.status === 'open' ? 'badge-critical' :
                          alertItem.status === 'acknowledged' ? 'badge-medium' : 'badge-benign'
                        }`}>
                          {alertItem.status}
                        </span>
                      </td>
                      <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', maxWidth: '280px' }}>
                        {alertItem.description}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: '0.35rem' }}>
                          <button
                            onClick={() => navigate(`/alerts/${alertItem._id}/investigate`)}
                            className="btn btn-primary"
                            style={{ padding: '0.25rem 0.5rem', fontSize: '0.725rem' }}
                            title="Investigate alert timeline & related activity"
                          >
                            <Search size={12} /> Investigate
                          </button>
                          {role !== 'VIEWER' && (
                            <>
                              {alertItem.status === 'open' && (
                                <button
                                  onClick={() => handleUpdateStatus(alertItem._id, 'acknowledged')}
                                  disabled={actionLoadingId === alertItem._id}
                                  className="btn"
                                  style={{ padding: '0.25rem 0.5rem', fontSize: '0.725rem' }}
                                >
                                  <Clock size={12} /> Ack
                                </button>
                              )}
                              {(alertItem.status === 'open' || alertItem.status === 'acknowledged') && (
                                <button
                                  onClick={() => handleUpdateStatus(alertItem._id, 'resolved')}
                                  disabled={actionLoadingId === alertItem._id}
                                  className="btn"
                                  style={{ padding: '0.25rem 0.5rem', fontSize: '0.725rem', borderColor: 'rgba(16, 185, 129, 0.4)', color: '#34d399' }}
                                >
                                  <CheckCircle2 size={12} /> Resolve
                                </button>
                              )}
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            <div className="pagination-bar">
              <div>
                Page <strong style={{ color: '#fff' }}>{pagination.page}</strong> of{' '}
                <strong style={{ color: '#fff' }}>{pagination.totalPages}</strong> ({pagination.total} total alerts)
              </div>
              <div className="pagination-buttons">
                <button
                  onClick={() => handlePageChange(pagination.page - 1)}
                  disabled={pagination.page <= 1}
                  className="btn"
                  style={{ padding: '0.35rem 0.75rem', fontSize: '0.8rem' }}
                >
                  <ChevronLeft size={14} /> Previous
                </button>
                <button
                  onClick={() => handlePageChange(pagination.page + 1)}
                  disabled={pagination.page >= pagination.totalPages}
                  className="btn"
                  style={{ padding: '0.35rem 0.75rem', fontSize: '0.8rem' }}
                >
                  Next <ChevronRight size={14} />
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
};

export default AlertsPage;
