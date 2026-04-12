// ─────────────────────────────────────────
//  Rate Limiting Middleware
// ─────────────────────────────────────────
const rateLimit = require('express-rate-limit');

/**
 * Rate limiter for scan endpoints.
 * 5 scans per IP per 15 minutes.
 */
const scanLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: {
    error: 'Too many scan requests. Please try again in 15 minutes.',
    code: 'RATE_LIMIT_SCAN',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * Rate limiter for auth endpoints.
 * 30 attempts per IP per 15 minutes.
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: {
    error: 'Too many authentication attempts. Please try again in 15 minutes.',
    code: 'RATE_LIMIT_AUTH',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * General API rate limiter.
 * 200 requests per IP per 15 minutes.
 */
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: {
    error: 'Too many requests. Please slow down.',
    code: 'RATE_LIMIT_GENERAL',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

module.exports = { scanLimiter, authLimiter, apiLimiter };
