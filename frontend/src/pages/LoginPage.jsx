// ─────────────────────────────────────────
//  Login Page
// ─────────────────────────────────────────
import { useState } from 'react';
import { Link, Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function LoginPage() {
  const { login, isAuthenticated } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!email.trim() || !password.trim()) {
      setError('Please fill in all fields.');
      return;
    }

    setLoading(true);
    try {
      await login(email.trim(), password);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-bg-effects">
        <div className="auth-orb auth-orb-1" />
        <div className="auth-orb auth-orb-2" />
        <div className="auth-orb auth-orb-3" />
      </div>

      <div className="auth-container">
        {/* Left panel — Branding */}
        <div className="auth-branding">
          <div className="auth-brand-content">
            <div className="auth-brand-icon">🛡️</div>
            <h1 className="auth-brand-title">Attack Path Discovery</h1>
            <p className="auth-brand-desc">
              Advanced cyber threat analysis and attack path visualization platform.
              Discover vulnerabilities, map exploits, and visualize attack chains.
            </p>
            <div className="auth-brand-features">
              <div className="auth-brand-feature">
                <span>🔍</span> Port & Service Discovery
              </div>
              <div className="auth-brand-feature">
                <span>🛡️</span> CVE Vulnerability Mapping
              </div>
              <div className="auth-brand-feature">
                <span>💀</span> Exploit Intelligence
              </div>
              <div className="auth-brand-feature">
                <span>🕸️</span> Attack Graph Visualization
              </div>
            </div>
          </div>
        </div>

        {/* Right panel — Form */}
        <div className="auth-form-panel">
          <div className="auth-form-wrapper">
            <div className="auth-form-header">
              <h2>Welcome Back</h2>
              <p>Sign in to your account to continue</p>
            </div>

            <form onSubmit={handleSubmit} className="auth-form" id="login-form">
              <div className="auth-field">
                <label htmlFor="login-email">Email Address</label>
                <div className="auth-input-wrapper">
                  <span className="auth-input-icon">✉</span>
                  <input
                    id="login-email"
                    type="email"
                    placeholder="you@example.com"
                    value={email}
                    onChange={(e) => { setEmail(e.target.value); setError(''); }}
                    disabled={loading}
                    autoComplete="email"
                    autoFocus
                  />
                </div>
              </div>

              <div className="auth-field">
                <label htmlFor="login-password">Password</label>
                <div className="auth-input-wrapper">
                  <span className="auth-input-icon">🔒</span>
                  <input
                    id="login-password"
                    type={showPassword ? 'text' : 'password'}
                    placeholder="Enter your password"
                    value={password}
                    onChange={(e) => { setPassword(e.target.value); setError(''); }}
                    disabled={loading}
                    autoComplete="current-password"
                  />
                  <button
                    type="button"
                    className="auth-toggle-password"
                    onClick={() => setShowPassword(!showPassword)}
                    tabIndex={-1}
                  >
                    {showPassword ? '🙈' : '👁'}
                  </button>
                </div>
              </div>

              {error && (
                <div className="auth-error">
                  <span>⚠</span> {error}
                </div>
              )}

              <button
                type="submit"
                className={`auth-submit-btn ${loading ? 'loading' : ''}`}
                disabled={loading}
                id="login-submit"
              >
                {loading ? (
                  <>
                    <span className="auth-spinner" />
                    Signing in...
                  </>
                ) : (
                  <>▶ Sign In</>
                )}
              </button>
            </form>

            <div className="auth-footer">
              Don't have an account?{' '}
              <Link to="/register" className="auth-link">
                Create one
              </Link>
            </div>
          </div>
        </div>
      </div>

      <div className="auth-disclaimer">
        ⚠️ Educational Use Only · Safe Non-Intrusive Analysis · No Exploitation Performed
      </div>
    </div>
  );
}
