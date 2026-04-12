// ─────────────────────────────────────────
//  Auth Context — React Context for auth state
// ─────────────────────────────────────────
import { createContext, useContext, useState, useEffect, useCallback } from 'react';

const AuthContext = createContext(null);

const API_BASE = 'http://localhost:4000/api';

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [loading, setLoading] = useState(true);

  // Initialize from localStorage on mount
  useEffect(() => {
    const savedToken = localStorage.getItem('apd_token');
    const savedUser = localStorage.getItem('apd_user');

    if (savedToken && savedUser) {
      try {
        setToken(savedToken);
        setUser(JSON.parse(savedUser));
      } catch {
        localStorage.removeItem('apd_token');
        localStorage.removeItem('apd_user');
      }
    }
    setLoading(false);
  }, []);

  // Verify token on load
  useEffect(() => {
    if (!token) return;

    fetch(`${API_BASE}/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => {
        if (!res.ok) throw new Error('Token invalid');
        return res.json();
      })
      .then((data) => {
        setUser(data.user);
        localStorage.setItem('apd_user', JSON.stringify(data.user));
      })
      .catch(() => {
        // Token expired or invalid
        logout();
      });
  }, [token]);

  const login = useCallback(async (email, password) => {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || 'Login failed');
    }

    setToken(data.token);
    setUser(data.user);
    localStorage.setItem('apd_token', data.token);
    localStorage.setItem('apd_user', JSON.stringify(data.user));

    return data;
  }, []);

  const register = useCallback(async (username, email, password) => {
    const res = await fetch(`${API_BASE}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password }),
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || 'Registration failed');
    }

    setToken(data.token);
    setUser(data.user);
    localStorage.setItem('apd_token', data.token);
    localStorage.setItem('apd_user', JSON.stringify(data.user));

    return data;
  }, []);

  const logout = useCallback(() => {
    setToken(null);
    setUser(null);
    localStorage.removeItem('apd_token');
    localStorage.removeItem('apd_user');
  }, []);

  const value = {
    user,
    token,
    loading,
    isAuthenticated: !!token && !!user,
    login,
    register,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

export default AuthContext;
