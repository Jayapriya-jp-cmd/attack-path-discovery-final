// ─────────────────────────────────────────
//  App — Root component with routing
// ─────────────────────────────────────────
import { useState, useEffect, useCallback } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { io } from 'socket.io-client';
import { AuthProvider } from './context/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import Sidebar from './components/Sidebar';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import HistoryPage from './pages/HistoryPage';
import ScanForm from './components/ScanForm';
import ScanProgress from './components/ScanProgress';
import Dashboard from './components/Dashboard';
import AttackGraph from './components/AttackGraph';
import AttackPaths from './components/AttackPaths';
import RiskScore from './components/RiskScore';
import ReportView from './components/ReportView';

const API_BASE = 'http://localhost:4000';

function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* Public routes */}
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />

          {/* Protected routes with sidebar layout */}
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <AppLayout />
              </ProtectedRoute>
            }
          />
          <Route
            path="/history"
            element={
              <ProtectedRoute>
                <HistoryLayout />
              </ProtectedRoute>
            }
          />

          {/* Default redirect */}
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}

/**
 * Main dashboard layout with sidebar
 */
function AppLayout() {
  const [scanData, setScanData] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(null);
  const [activeView, setActiveView] = useState('dashboard');

  // Socket.IO connection for real-time progress
  useEffect(() => {
    const socket = io(API_BASE, { transports: ['websocket', 'polling'] });

    socket.on('connect', () => {
      console.log('[Socket.IO] Connected');
    });

    socket.on('scan:progress', (data) => {
      setProgress(data);
    });

    socket.on('scan:complete', () => {
      setProgress(null);
    });

    socket.on('scan:error', (data) => {
      console.error('[Socket.IO] Scan error:', data.error);
      setProgress(null);
    });

    return () => socket.disconnect();
  }, []);

  const handleScanStart = useCallback((target) => {
    setIsScanning(true);
    setScanData(null);
    setProgress({ phase: 'Initializing', progress: 0, message: `Starting scan for ${target}...` });
    setActiveView('dashboard');
  }, []);

  const handleScanComplete = useCallback((data) => {
    setIsScanning(false);
    setScanData(data);
    setProgress(null);
  }, []);

  const handleScanError = useCallback(() => {
    setIsScanning(false);
    setProgress(null);
  }, []);

  // Allow loading scan data from history page
  const handleLoadScan = useCallback((data) => {
    setScanData(data);
    setIsScanning(false);
    setProgress(null);
  }, []);

  // Store handleLoadScan in global scope for cross-page communication
  useEffect(() => {
    window.__apdLoadScan = handleLoadScan;
    return () => { delete window.__apdLoadScan; };
  }, [handleLoadScan]);

  const views = [
    { key: 'dashboard', label: '📊 Dashboard' },
    { key: 'graph', label: '🕸️ Attack Graph' },
    { key: 'paths', label: '⚡ Attack Paths' },
    { key: 'report', label: '📋 Report' },
  ];

  return (
    <div className="layout">
      <Sidebar />
      <main className="main-content">
        <div className="app-container">
          {/* Header */}
          <header className="app-header">
            <div className="app-logo">
              <div className="app-logo-icon">🛡️</div>
              <div>
                <h1>Attack Path Discovery</h1>
                <div className="app-logo-subtitle">Cyber Threat Analysis Platform</div>
              </div>
            </div>
            <div className="app-status">
              <div className="status-dot" />
              <span>System Online · Real Execution Only</span>
            </div>
          </header>

          {/* Scan Form */}
          <ScanForm
            isScanning={isScanning}
            onScanStart={handleScanStart}
            onScanComplete={handleScanComplete}
            onScanError={handleScanError}
          />

          {/* Progress */}
          {isScanning && <ScanProgress progress={progress} />}

          {/* Results */}
          {scanData ? (
            <>
              {/* Stats Summary */}
              <div className="stats-grid fade-in">
                <StatCard value={scanData.summary?.totalPorts || 0} label="Open Ports" />
                <StatCard value={scanData.summary?.totalVulnerabilities || 0} label="Vulnerabilities" />
                <StatCard value={scanData.summary?.totalExploits || 0} label="Exploits" />
                <StatCard value={scanData.summary?.totalPrivEscVectors || 0} label="PrivEsc Vectors" />
                <StatCard value={scanData.summary?.totalAttackPaths || 0} label="Attack Paths" />
                <StatCard value={scanData.summary?.highestRisk || 0} label="Risk Score" />
              </div>

              {/* View Tabs */}
              <div className="tabs">
                {views.map((view) => (
                  <button
                    key={view.key}
                    className={`tab-btn ${activeView === view.key ? 'active' : ''}`}
                    onClick={() => setActiveView(view.key)}
                    id={`view-${view.key}`}
                  >
                    {view.label}
                  </button>
                ))}
              </div>

              {/* Content */}
              <div className="content-grid">
                <div className="content-main">
                  {activeView === 'dashboard' && <Dashboard data={scanData} />}
                  {activeView === 'graph' && <AttackGraph data={scanData} />}
                  {activeView === 'paths' && <AttackPaths paths={scanData.attackPaths} />}
                  {activeView === 'report' && <ReportView data={scanData} />}
                </div>
                <div className="content-sidebar">
                  <RiskScore data={scanData} />
                  {scanData.os && (
                    <div className="glass-card fade-in">
                      <div className="card-header">
                        <div className="card-title">
                          <span className="icon">💻</span>
                          Target Info
                        </div>
                      </div>
                      <div style={{ fontSize: '0.85rem', fontFamily: 'var(--font-mono)' }}>
                        <InfoRow label="Target" value={scanData.target} />
                        <InfoRow label="OS" value={scanData.os.name} />
                        <InfoRow label="Family" value={scanData.os.family} />
                        <InfoRow label="Accuracy" value={`${scanData.os.accuracy}%`} />
                        <InfoRow label="Scan Time" value={scanData.duration} />
                        <InfoRow label="Scan ID" value={scanData.scanId?.substring(0, 8) + '...'} />
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </>
          ) : !isScanning ? (
            <WelcomeScreen />
          ) : null}

          {/* Footer */}
          <footer style={{
            textAlign: 'center',
            padding: '32px 0',
            borderTop: '1px solid var(--border-subtle)',
            marginTop: '40px',
            color: 'var(--text-muted)',
            fontSize: '0.75rem',
            fontFamily: 'var(--font-mono)',
          }}>
            <div>⚠️ Educational Use Only · Safe Non-Intrusive Analysis · No Exploitation Performed</div>
            <div style={{ marginTop: '4px' }}>Attack Path Discovery v2.0.0</div>
          </footer>
        </div>
      </main>
    </div>
  );
}

/**
 * History page layout with sidebar
 */
function HistoryLayout() {
  const handleLoadScan = (data) => {
    if (window.__apdLoadScan) {
      window.__apdLoadScan(data);
    }
  };

  return (
    <div className="layout">
      <Sidebar />
      <main className="main-content">
        <div className="app-container">
          <HistoryPage onLoadScan={handleLoadScan} />
        </div>
      </main>
    </div>
  );
}

function StatCard({ value, label }) {
  return (
    <div className="stat-card">
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

function InfoRow({ label, value }) {
  return (
    <div style={{
      display: 'flex',
      justifyContent: 'space-between',
      padding: '8px 0',
      borderBottom: '1px solid var(--border-subtle)',
    }}>
      <span style={{ color: 'var(--text-muted)' }}>{label}</span>
      <span style={{ color: 'var(--text-primary)' }}>{value}</span>
    </div>
  );
}

function WelcomeScreen() {
  return (
    <div className="welcome-screen">
      <div className="welcome-icon">🛡️</div>
      <h2 className="welcome-title">Ready to Discover Attack Paths</h2>
      <p className="welcome-desc">
        Enter a target IP address or domain above to begin safe, non-intrusive
        vulnerability assessment and generate interactive attack path visualizations.
      </p>
      <div className="welcome-features">
        <div className="welcome-feature">
          <div className="welcome-feature-icon">🔍</div>
          <div className="welcome-feature-label">Port & Service Discovery</div>
        </div>
        <div className="welcome-feature">
          <div className="welcome-feature-icon">🛡️</div>
          <div className="welcome-feature-label">CVE Vulnerability Mapping</div>
        </div>
        <div className="welcome-feature">
          <div className="welcome-feature-icon">💀</div>
          <div className="welcome-feature-label">Exploit Intelligence</div>
        </div>
        <div className="welcome-feature">
          <div className="welcome-feature-icon">🕸️</div>
          <div className="welcome-feature-label">Attack Graph Generation</div>
        </div>
        <div className="welcome-feature">
          <div className="welcome-feature-icon">⚡</div>
          <div className="welcome-feature-label">Ranked Attack Paths</div>
        </div>
      </div>
    </div>
  );
}

export default App;
