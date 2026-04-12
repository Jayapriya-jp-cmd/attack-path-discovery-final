// ─────────────────────────────────────────
//  History Page — View past scans
// ─────────────────────────────────────────
import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const API_BASE = 'http://localhost:4000/api';

export default function HistoryPage({ onLoadScan }) {
  const { token } = useAuth();
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [page, setPage] = useState(1);
  const [pagination, setPagination] = useState(null);

  const fetchHistory = async (pageNum = 1) => {
    setLoading(true);
    setError('');

    try {
      const res = await fetch(`${API_BASE}/history?page=${pageNum}&limit=10`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      const data = await res.json();

      if (!res.ok) throw new Error(data.error || 'Failed to load history');

      setScans(data.data || []);
      setPagination(data.pagination || null);
      setPage(pageNum);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const handleViewScan = async (scanId) => {
    try {
      const res = await fetch(`${API_BASE}/history/${scanId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      const data = await res.json();

      if (!res.ok) throw new Error(data.error || 'Failed to load scan');

      // Re-construct result format that the dashboard expects
      const scanData = data.data;
      const result = {
        scanId: scanData.scanId,
        target: scanData.target,
        scanTime: scanData.scanResult?.scanTime,
        duration: scanData.duration,
        os: scanData.os,
        ports: scanData.ports,
        services: scanData.services,
        vulnerabilities: scanData.vulnerabilities,
        exploits: scanData.exploits,
        privEscVectors: scanData.privEscVectors,
        adAnalysis: scanData.adAnalysis,
        graph: scanData.graphData,
        attackPaths: scanData.attackPaths,
        summary: scanData.summary,
      };

      if (onLoadScan) {
        onLoadScan(result);
        navigate('/dashboard');
      }
    } catch (err) {
      setError(err.message);
    }
  };

  const handleDeleteScan = async (scanId) => {
    if (!confirm('Delete this scan from history?')) return;

    try {
      const res = await fetch(`${API_BASE}/history/${scanId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Delete failed');
      }

      setScans((prev) => prev.filter((s) => s.scanId !== scanId));
    } catch (err) {
      setError(err.message);
    }
  };

  const getSeverityClass = (severity) => {
    if (!severity) return 'badge-info';
    switch (severity.toLowerCase()) {
      case 'critical': return 'badge-critical';
      case 'high': return 'badge-high';
      case 'medium': return 'badge-medium';
      case 'low': return 'badge-low';
      default: return 'badge-info';
    }
  };

  return (
    <div className="history-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <span className="icon">📜</span>
            Scan History
          </h1>
          <p className="page-subtitle">View and manage your past reconnaissance scans</p>
        </div>
        <button className="refresh-btn" onClick={() => fetchHistory(page)} id="refresh-history">
          🔄 Refresh
        </button>
      </div>

      {error && (
        <div className="auth-error" style={{ marginBottom: '20px' }}>
          <span>⚠</span> {error}
        </div>
      )}

      {loading ? (
        <div className="history-loading">
          <div className="auth-loading-spinner" />
          <p>Loading scan history...</p>
        </div>
      ) : scans.length === 0 ? (
        <div className="history-empty">
          <div className="history-empty-icon">🔍</div>
          <h3>No Scans Yet</h3>
          <p>Run your first scan from the Dashboard to see results here.</p>
          <button
            className="scan-btn"
            onClick={() => navigate('/dashboard')}
            style={{ marginTop: '16px' }}
          >
            ▶ Go to Dashboard
          </button>
        </div>
      ) : (
        <>
          <div className="history-list">
            {scans.map((scan) => (
              <div key={scan.scanId} className="history-card glass-card">
                <div className="history-card-header">
                  <div className="history-card-target">
                    <span className="history-target-icon">🎯</span>
                    <span className="history-target-text">{scan.target}</span>
                  </div>
                  <div className="history-card-actions">
                    <button
                      className="history-view-btn"
                      onClick={() => handleViewScan(scan.scanId)}
                      title="View details"
                    >
                      👁 View
                    </button>
                    <button
                      className="history-delete-btn"
                      onClick={() => handleDeleteScan(scan.scanId)}
                      title="Delete scan"
                    >
                      🗑
                    </button>
                  </div>
                </div>

                <div className="history-card-body">
                  <div className="history-stats">
                    <div className="history-stat">
                      <span className="history-stat-value">{scan.summary?.totalPorts || 0}</span>
                      <span className="history-stat-label">Ports</span>
                    </div>
                    <div className="history-stat">
                      <span className="history-stat-value">{scan.summary?.totalVulnerabilities || 0}</span>
                      <span className="history-stat-label">Vulns</span>
                    </div>
                    <div className="history-stat">
                      <span className="history-stat-value">{scan.summary?.totalExploits || 0}</span>
                      <span className="history-stat-label">Exploits</span>
                    </div>
                    <div className="history-stat">
                      <span className="history-stat-value">{scan.summary?.totalAttackPaths || 0}</span>
                      <span className="history-stat-label">Paths</span>
                    </div>
                    <div className="history-stat">
                      <span
                        className={`card-badge ${getSeverityClass(scan.summary?.overallSeverity)}`}
                        style={{ fontSize: '0.75rem' }}
                      >
                        {scan.summary?.overallSeverity || 'N/A'}
                      </span>
                      <span className="history-stat-label">Severity</span>
                    </div>
                  </div>

                  <div className="history-card-meta">
                    <span className="history-meta-item">
                      🕐 {scan.duration || 'N/A'}
                    </span>
                    <span className="history-meta-item">
                      📅 {new Date(scan.createdAt).toLocaleString()}
                    </span>
                    <span className="history-meta-item history-scanid">
                      ID: {scan.scanId?.substring(0, 8)}...
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Pagination */}
          {pagination && pagination.totalPages > 1 && (
            <div className="history-pagination">
              <button
                className="pagination-btn"
                disabled={page <= 1}
                onClick={() => fetchHistory(page - 1)}
              >
                ◀ Previous
              </button>
              <span className="pagination-info">
                Page {pagination.page} of {pagination.totalPages}
              </span>
              <button
                className="pagination-btn"
                disabled={page >= pagination.totalPages}
                onClick={() => fetchHistory(page + 1)}
              >
                Next ▶
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
