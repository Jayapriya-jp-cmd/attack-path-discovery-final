// ─────────────────────────────────────────
//  JWT Authentication Middleware
// ─────────────────────────────────────────
const jwt = require('jsonwebtoken');
const config = require('../config');

/**
 * Verify JWT token from Authorization header.
 * Attaches decoded user to req.user on success.
 */
function authMiddleware(req, res, next) {
  // Get token from header
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Access denied. No token provided.',
      code: 'NO_TOKEN',
    });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, config.jwt.secret);
    req.user = {
      id: decoded.id,
      username: decoded.username,
      email: decoded.email,
    };
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Token expired. Please log in again.',
        code: 'TOKEN_EXPIRED',
      });
    }
    return res.status(401).json({
      error: 'Invalid token.',
      code: 'INVALID_TOKEN',
    });
  }
}

/**
 * Optional auth — attaches user if token is present, but doesn't block.
 */
function optionalAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return next();
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, config.jwt.secret);
    req.user = {
      id: decoded.id,
      username: decoded.username,
      email: decoded.email,
    };
  } catch {
    // Token invalid — proceed without user
  }
  next();
}

module.exports = { authMiddleware, optionalAuth };
