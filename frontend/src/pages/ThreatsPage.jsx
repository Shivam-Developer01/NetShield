import React, { useState, useEffect } from 'react';
import { Activity, Search, Filter, ChevronLeft, ChevronRight, Eye, X } from 'lucide-react';
import { getPredictions } from '../services/socService';
import LoadingSpinner from '../components/common/LoadingSpinner';
import ErrorBanner from '../components/common/ErrorBanner';
import SeverityBadge from '../components/common/SeverityBadge';

const ThreatsPage = ({ globalDatasetFilter }) => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [predictions, setPredictions] = useState([]);
  const [pagination, setPagination] = useState({ page: 1, limit: 20, total: 0, totalPages: 1 });
  
  // Local filters
  const [datasetFilter, setDatasetFilter] = useState(globalDatasetFilter || 'all');
  const [predictionFilter, setPredictionFilter] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);

  useEffect(() => {
    setDatasetFilter(globalDatasetFilter);
  }, [globalDatasetFilter]);

  const fetchLogs = async (pageNumber = 1) => {
    setLoading(true);
    setError(null);
    try {
      const res = await getPredictions({
        page: pageNumber,
        limit: 20,
        datasetType: datasetFilter,
        prediction: predictionFilter
      });
      setPredictions(res.data || []);
      if (res.pagination) {
        setPagination(res.pagination);
      }
    } catch (err) {
      setError(err.message || 'Failed to fetch threat logs.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs(1);
  }, [datasetFilter, predictionFilter]);

  const handlePageChange = (newPage) => {
    if (newPage >= 1 && newPage <= pagination.totalPages) {
      fetchLogs(newPage);
    }
  };

  return (
    <div>
      {/* Page Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.35rem', fontWeight: 700, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Activity size={22} style={{ color: 'var(--accent-cyan)' }} />
            Threat Predictions & Traffic Feed
          </h2>
          <p style={{ fontSize: '0.825rem', color: 'var(--text-muted)', margin: '0.2rem 0 0 0' }}>
            Real-time and batch intrusion prediction logs persisted by NetShield
          </p>
        </div>

        {/* Filter Controls Bar */}
        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <Filter size={14} style={{ color: 'var(--text-muted)' }} />
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

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <Search size={14} style={{ color: 'var(--text-muted)' }} />
            <select
              value={predictionFilter}
              onChange={(e) => setPredictionFilter(e.target.value)}
              className="form-select"
              style={{ padding: '0.4rem 0.75rem', fontSize: '0.8rem' }}
            >
              <option value="all">All Predictions</option>
              <option value="Normal">Normal (Benign)</option>
              <option value="BENIGN">BENIGN (Clean)</option>
              <option value="DoS">DoS</option>
              <option value="DDoS">DDoS</option>
              <option value="Probe">Probe</option>
              <option value="PortScan">PortScan</option>
              <option value="R2L">R2L</option>
              <option value="U2R">U2R</option>
            </select>
          </div>
        </div>
      </div>

      {error && <ErrorBanner message={error} onRetry={() => fetchLogs(pagination.page)} />}

      {/* Prediction Table Card */}
      <div className="soc-card">
        {loading ? (
          <LoadingSpinner message="Querying threat prediction logs..." />
        ) : predictions.length === 0 ? (
          <div style={{ padding: '3rem 1.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
            <Activity size={36} style={{ color: 'var(--border-color)', marginBottom: '0.75rem' }} />
            <p style={{ fontSize: '0.95rem', fontWeight: 500 }}>No prediction logs match your current query filters.</p>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Submit test predictions via Manual Predict to populate feed.</p>
          </div>
        ) : (
          <>
            <div className="table-container">
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Dataset</th>
                    <th>Prediction</th>
                    <th>Confidence</th>
                    <th>Model Version</th>
                    <th>Latency</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {predictions.map((log) => (
                    <tr key={log._id}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.775rem' }}>
                        {new Date(log.timestamp).toLocaleString()}
                      </td>
                      <td style={{ textTransform: 'uppercase', fontSize: '0.775rem', fontWeight: 600, color: 'var(--accent-cyan)' }}>
                        {log.datasetType}
                      </td>
                      <td>
                        <SeverityBadge 
                          prediction={log.prediction}
                          isBenign={log.prediction === 'Normal' || log.prediction === 'BENIGN'}
                        />
                        {log.sourceInfo?.groundTruth && (
                          <div style={{ fontSize: '0.68rem', color: '#94a3b8', marginTop: '0.15rem' }}>
                            GT: <span style={{ color: '#cbd5e1', fontWeight: 600 }}>{log.sourceInfo.groundTruth}</span>
                          </div>
                        )}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                        {(log.confidence * 100).toFixed(2)}%
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                        {log.modelVersion}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {log.processingLatencyMs} ms
                      </td>
                      <td>
                        <button
                          onClick={() => setSelectedLog(log)}
                          className="btn"
                          style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }}
                        >
                          <Eye size={13} />
                          Details
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div className="pagination-bar">
              <div>
                Showing page <strong style={{ color: '#fff' }}>{pagination.page}</strong> of{' '}
                <strong style={{ color: '#fff' }}>{pagination.totalPages}</strong> ({pagination.total} total logs)
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

      {/* Log Detail Modal */}
      {selectedLog && (
        <div style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(5, 8, 15, 0.85)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: '1rem'
        }}>
          <div className="soc-card" style={{ maxWidth: '560px', width: '100%', border: '1px solid var(--accent-cyan)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.75rem' }}>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#f8fafc', margin: 0 }}>
                Prediction Telemetry Details
              </h3>
              <button onClick={() => setSelectedLog(null)} style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                <X size={20} />
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', fontSize: '0.85rem', marginBottom: '1.25rem' }}>
              <div><strong>Log ID:</strong> <code style={{ fontSize: '0.75rem' }}>{selectedLog._id}</code></div>
              <div><strong>Timestamp:</strong> {new Date(selectedLog.timestamp).toLocaleString()}</div>
              <div><strong>Dataset:</strong> {selectedLog.datasetType.toUpperCase()}</div>
              <div><strong>ML Prediction:</strong> <code style={{ color: 'var(--accent-cyan)' }}>{selectedLog.prediction}</code></div>
              {selectedLog.sourceInfo?.groundTruth ? (
                <div><strong>Ground Truth:</strong> <code style={{ color: '#f87171' }}>{selectedLog.sourceInfo.groundTruth}</code></div>
              ) : (
                <div><strong>Ground Truth:</strong> <span style={{ color: 'var(--text-muted)' }}>Not specified</span></div>
              )}
              <div><strong>Confidence:</strong> {(selectedLog.confidence * 100).toFixed(2)}%</div>
              <div><strong>Model Version:</strong> {selectedLog.modelVersion}</div>
              <div><strong>Latency:</strong> {selectedLog.processingLatencyMs} ms</div>
              <div><strong>Records Processed:</strong> {selectedLog.recordsProcessed}</div>
            </div>

            {selectedLog.classProbabilities && (
              <div>
                <h4 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                  Model Class Probabilities:
                </h4>
                <div style={{ background: '#0f172a', padding: '0.75rem', borderRadius: '8px', border: '1px solid var(--border-color)', maxHeight: '160px', overflowY: 'auto' }}>
                  {Object.entries(selectedLog.classProbabilities).map(([cls, prob]) => (
                    <div key={cls} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', padding: '0.2rem 0' }}>
                      <span style={{ color: 'var(--text-primary)' }}>{cls}</span>
                      <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>{(prob * 100).toFixed(3)}%</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '1.25rem' }}>
              <button onClick={() => setSelectedLog(null)} className="btn btn-primary">Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatsPage;
