// ─────────────────────────────────────────
//  Scan Form — Now sends JWT in Authorization header
// ─────────────────────────────────────────
import { useState } from 'react';
import { useAuth } from '../context/AuthContext';

const API_BASE = 'http://localhost:4000/api';

export default function ScanForm({ onScanStart, onScanComplete, onScanError, isScanning }) {
  const { token } = useAuth();
  const [target, setTarget] = useState('');
  const [error, setError] = useState('');

  const validate = (value) => {
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    return ipRegex.test(value) || domainRegex.test(value) || cidrRegex.test(value);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!target.trim()) {
      setError('Please enter a target IP or domain');
      return;
    }

    if (!validate(target.trim())) {
      setError('Invalid format. Enter a valid IP address or domain name.');
      return;
    }

    onScanStart(target.trim());

    try {
      const headers = {
        'Content-Type': 'application/json',
      };

      // Send JWT in Authorization header
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      const res = await fetch(`${API_BASE}/scan`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ target: target.trim() }),
      });

      const data = await res.json();

      if (!res.ok || data.status === 'error') {
        throw new Error(data.message || data.error || 'Scan failed');
      }

      onScanComplete(data);
    } catch (err) {
      setError(err.message);
      onScanError(err.message);
    }
  };

  return (
    <div className="scan-form-container glass-card">
      <div className="card-header">
        <div className="card-title">
          <span className="icon">🎯</span>
          Target Scanner
        </div>
        <span className="card-badge badge-info">REAL MODE</span>
      </div>
      <form className="scan-form" onSubmit={handleSubmit} id="scan-form">
        <div className="scan-input-wrapper">
          <span className="scan-input-icon">⟩</span>
          <input
            id="scan-target-input"
            type="text"
            className="scan-input"
            placeholder="Enter target IP or domain (e.g., 192.168.1.100)"
            value={target}
            onChange={(e) => { setTarget(e.target.value); setError(''); }}
            disabled={isScanning}
            autoComplete="off"
            spellCheck="false"
          />
        </div>
        <button
          id="scan-submit-btn"
          type="submit"
          className={`scan-btn ${isScanning ? 'scanning' : ''}`}
          disabled={isScanning}
        >
          {isScanning ? (
            <>⟳ Scanning...</>
          ) : (
            <>▶ Launch Scan</>
          )}
        </button>
      </form>
      {error && (
        <div style={{
          marginTop: '12px',
          color: 'var(--severity-critical)',
          fontSize: '0.8rem',
          fontFamily: 'var(--font-mono)',
        }}>
          ⚠ {error}
        </div>
      )}
    </div>
  );
}
