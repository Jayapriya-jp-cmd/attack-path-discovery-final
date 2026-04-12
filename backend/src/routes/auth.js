// ─────────────────────────────────────────
//  Auth Routes — POST /api/auth/*
// ─────────────────────────────────────────
const { Router } = require('express');
const jwt = require('jsonwebtoken');
const config = require('../config');
const User = require('../models/User');
const { authMiddleware } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimiter');
const mongo = require('../db/mongo');

const router = Router();

// Apply rate limiting to all auth routes
router.use(authLimiter);

/**
 * Generate JWT token for a user.
 */
function generateToken(user) {
  return jwt.sign(
    {
      id: user._id,
      username: user.username,
      email: user.email,
    },
    config.jwt.secret,
    { expiresIn: config.jwt.expiresIn }
  );
}

/**
 * POST /api/auth/register
 * Create a new user account.
 */
router.post('/register', async (req, res) => {
  try {
    if (!mongo.isConnected()) {
      return res.status(503).json({
        error: 'Database unavailable. Please try again later.',
      });
    }

    const { username, email, password } = req.body;

    // Validate input
    if (!username || !email || !password) {
      return res.status(400).json({
        error: 'Username, email, and password are required.',
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: 'Password must be at least 6 characters.',
      });
    }

    // Check for existing user
    const existingUser = await User.findOne({
      $or: [{ email: email.toLowerCase() }, { username }],
    });

    if (existingUser) {
      const field = existingUser.email === email.toLowerCase() ? 'email' : 'username';
      return res.status(409).json({
        error: `An account with this ${field} already exists.`,
      });
    }

    // Create user
    const user = new User({ username, email, password });
    await user.save();

    // Generate token
    const token = generateToken(user);

    console.log(`[Auth] New user registered: ${username} (${email})`);

    res.status(201).json({
      status: 'success',
      message: 'Account created successfully.',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        createdAt: user.createdAt,
      },
    });
  } catch (err) {
    console.error('[Auth] Registration error:', err.message);

    // Handle Mongoose validation errors
    if (err.name === 'ValidationError') {
      const messages = Object.values(err.errors).map((e) => e.message);
      return res.status(400).json({ error: messages.join(', ') });
    }

    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

/**
 * POST /api/auth/login
 * Authenticate user and return JWT.
 */
router.post('/login', async (req, res) => {
  try {
    if (!mongo.isConnected()) {
      return res.status(503).json({
        error: 'Database unavailable. Please try again later.',
      });
    }

    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: 'Email and password are required.',
      });
    }

    // Find user (explicitly include password field)
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');

    if (!user) {
      return res.status(401).json({
        error: 'Invalid email or password.',
      });
    }

    // Verify password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({
        error: 'Invalid email or password.',
      });
    }

    // Generate token
    const token = generateToken(user);

    console.log(`[Auth] User logged in: ${user.username}`);

    res.json({
      status: 'success',
      message: 'Login successful.',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        createdAt: user.createdAt,
      },
    });
  } catch (err) {
    console.error('[Auth] Login error:', err.message);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

/**
 * GET /api/auth/me
 * Return current authenticated user info.
 */
router.get('/me', authMiddleware, async (req, res) => {
  try {
    if (!mongo.isConnected()) {
      // Return user info from token if DB is down
      return res.json({
        user: {
          id: req.user.id,
          username: req.user.username,
          email: req.user.email,
        },
      });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }

    res.json({
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        createdAt: user.createdAt,
      },
    });
  } catch (err) {
    console.error('[Auth] Get user error:', err.message);
    res.status(500).json({ error: 'Failed to retrieve user info.' });
  }
});

module.exports = router;
