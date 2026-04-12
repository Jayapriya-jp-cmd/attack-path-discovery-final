// ─────────────────────────────────────────
//  Register Page
// ─────────────────────────────────────────
import { useState } from 'react';
import { Link, Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function RegisterPage() {
  const { register, isAuthenticated } = useAuth();
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  const validateForm = () => {
    if (!username.trim() || !email.trim() || !password || !confirmPassword) {
      return 'Please fill in all fields.';
    }
    if (username.trim().length < 3) {
      return 'Username must be at least 3 characters.';
    }
    if (!/^\S+@\S+\.\S+$/.test(email)) {
      return 'Please enter a valid email address.';
    }
    if (password.length < 6) {
      return 'Password must be at least 6 characters.';
    }
    if (password !== confirmPassword) {
      return 'Passwords do not match.';
    }
    return null;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    const validationError = validateForm();
    if (validationError) {
      setError(validationError);
      return;
    }

    setLoading(true);
    try {
      await register(username.trim(), email.trim(), password);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Password strength indicator
  const getPasswordStrength = () => {
    if (!password) return { level: 0, label: '', color: '' };
    let score = 0;
    if (password.length >= 6) score++;
    if (password.length >= 10) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;

    if (score <= 1) return { level: 1, label: 'Weak', color: 'var(--severity-critical)' };
    if (score <= 2) return { level: 2, label: 'Fair', color: 'var(--severity-medium)' };
    if (score <= 3) return { level: 3, label: 'Good', color: 'var(--severity-low)' };
    return { level: 4, label: 'Strong', color: 'var(--neon-cyan)' };
  };

  const strength = getPasswordStrength();

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
            <h1 className="auth-brand-title">Join APD</h1>
            <p className="auth-brand-desc">
              Create your account to start discovering attack paths, mapping vulnerabilities,
              and securing your infrastructure through safe, non-intrusive analysis.
            </p>
            <div className="auth-brand-features">
              <div className="auth-brand-feature">
                <span>⚡</span> Real-time Scan Progress
              </div>
              <div className="auth-brand-feature">
                <span>📊</span> Interactive Dashboards
              </div>
              <div className="auth-brand-feature">
                <span>📜</span> Scan History & Reports
              </div>
              <div className="auth-brand-feature">
                <span>🔐</span> Secure Authentication
              </div>
            </div>
          </div>
        </div>

        {/* Right panel — Form */}
        <div className="auth-form-panel">
          <div className="auth-form-wrapper">
            <div className="auth-form-header">
              <h2>Create Account</h2>
              <p>Set up your secure APD account</p>
            </div>

            <form onSubmit={handleSubmit} className="auth-form" id="register-form">
              <div className="auth-field">
                <label htmlFor="register-username">Username</label>
                <div className="auth-input-wrapper">
                  <span className="auth-input-icon">👤</span>
                  <input
                    id="register-username"
                    type="text"
                    placeholder="Choose a username"
                    value={username}
                    onChange={(e) => { setUsername(e.target.value); setError(''); }}
                    disabled={loading}
                    autoComplete="username"
                    autoFocus
                  />
                </div>
              </div>

              <div className="auth-field">
                <label htmlFor="register-email">Email Address</label>
                <div className="auth-input-wrapper">
                  <span className="auth-input-icon">✉</span>
                  <input
                    id="register-email"
                    type="email"
                    placeholder="you@example.com"
                    value={email}
                    onChange={(e) => { setEmail(e.target.value); setError(''); }}
                    disabled={loading}
                    autoComplete="email"
                  />
                </div>
              </div>

              <div className="auth-field">
                <label htmlFor="register-password">Password</label>
                <div className="auth-input-wrapper">
                  <span className="auth-input-icon">🔒</span>
                  <input
                    id="register-password"
                    type={showPassword ? 'text' : 'password'}
                    placeholder="Min 6 characters"
                    value={password}
                    onChange={(e) => { setPassword(e.target.value); setError(''); }}
                    disabled={loading}
                    autoComplete="new-password"
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
                {password && (
                  <div className="auth-password-strength">
                    <div className="auth-strength-bar">
                      {[1, 2, 3, 4].map((i) => (
                        <div
                          key={i}
                          className="auth-strength-segment"
                          style={{
                            background: i <= strength.level ? strength.color : 'var(--bg-secondary)',
                          }}
                        />
                      ))}
                    </div>
                    <span style={{ color: strength.color }}>{strength.label}</span>
                  </div>
                )}
              </div>

              <div className="auth-field">
                <label htmlFor="register-confirm">Confirm Password</label>
                <div className="auth-input-wrapper">
                  <span className="auth-input-icon">🔒</span>
                  <input
                    id="register-confirm"
                    type="password"
                    placeholder="Confirm your password"
                    value={confirmPassword}
                    onChange={(e) => { setConfirmPassword(e.target.value); setError(''); }}
                    disabled={loading}
                    autoComplete="new-password"
                  />
                  {confirmPassword && (
                    <span className="auth-match-indicator">
                      {password === confirmPassword ? '✓' : '✗'}
                    </span>
                  )}
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
                id="register-submit"
              >
                {loading ? (
                  <>
                    <span className="auth-spinner" />
                    Creating account...
                  </>
                ) : (
                  <>🚀 Create Account</>
                )}
              </button>
            </form>

            <div className="auth-footer">
              Already have an account?{' '}
              <Link to="/login" className="auth-link">
                Sign in
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
