// ─────────────────────────────────────────
//  Sidebar Navigation
// ─────────────────────────────────────────
import { useState } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Sidebar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const navItems = [
    { to: '/dashboard', icon: '📊', label: 'Dashboard' },
    { to: '/history', icon: '📜', label: 'History' },
  ];

  return (
    <>
      {/* Mobile toggle button */}
      <button
        className="sidebar-mobile-toggle"
        onClick={() => setMobileOpen(!mobileOpen)}
        id="sidebar-toggle"
      >
        {mobileOpen ? '✕' : '☰'}
      </button>

      {/* Overlay for mobile */}
      {mobileOpen && (
        <div
          className="sidebar-overlay"
          onClick={() => setMobileOpen(false)}
        />
      )}

      <aside className={`sidebar ${collapsed ? 'collapsed' : ''} ${mobileOpen ? 'mobile-open' : ''}`}>
        {/* Logo */}
        <div className="sidebar-header">
          <div className="sidebar-logo">
            <div className="sidebar-logo-icon">🛡️</div>
            {!collapsed && (
              <div className="sidebar-logo-text">
                <h2>APD</h2>
                <span>Attack Path Discovery</span>
              </div>
            )}
          </div>
          <button
            className="sidebar-collapse-btn"
            onClick={() => setCollapsed(!collapsed)}
            title={collapsed ? 'Expand' : 'Collapse'}
          >
            {collapsed ? '▸' : '◂'}
          </button>
        </div>

        {/* Navigation */}
        <nav className="sidebar-nav">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `sidebar-nav-item ${isActive ? 'active' : ''}`
              }
              onClick={() => setMobileOpen(false)}
              id={`nav-${item.label.toLowerCase()}`}
            >
              <span className="sidebar-nav-icon">{item.icon}</span>
              {!collapsed && <span className="sidebar-nav-label">{item.label}</span>}
            </NavLink>
          ))}
        </nav>

        {/* User info + Logout */}
        <div className="sidebar-footer">
          {user && !collapsed && (
            <div className="sidebar-user">
              <div className="sidebar-user-avatar">
                {user.username?.charAt(0).toUpperCase()}
              </div>
              <div className="sidebar-user-info">
                <div className="sidebar-user-name">{user.username}</div>
                <div className="sidebar-user-email">{user.email}</div>
              </div>
            </div>
          )}
          <button
            className="sidebar-logout-btn"
            onClick={handleLogout}
            id="logout-btn"
            title="Logout"
          >
            <span>🚪</span>
            {!collapsed && <span>Logout</span>}
          </button>
        </div>
      </aside>
    </>
  );
}
