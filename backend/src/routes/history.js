// ─────────────────────────────────────────
//  History Routes — GET /api/history
// ─────────────────────────────────────────
const { Router } = require('express');
const { authMiddleware } = require('../middleware/auth');
const Scan = require('../models/Scan');
const mongo = require('../db/mongo');

const router = Router();

// All history routes require authentication
router.use(authMiddleware);

/**
 * GET /api/history
 * Return all scans for the authenticated user, newest first.
 * Supports pagination via ?page=1&limit=20
 */
router.get('/', async (req, res) => {
  try {
    if (!mongo.isConnected()) {
      return res.status(503).json({
        error: 'Database unavailable. Scan history requires MongoDB.',
      });
    }

    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 20));
    const skip = (page - 1) * limit;

    const [scans, total] = await Promise.all([
      Scan.find({ userId: req.user.id })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .select('scanId target summary duration os createdAt')
        .lean(),
      Scan.countDocuments({ userId: req.user.id }),
    ]);

    res.json({
      status: 'success',
      data: scans,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (err) {
    console.error('[History] Fetch error:', err.message);
    res.status(500).json({ error: 'Failed to retrieve scan history.' });
  }
});

/**
 * GET /api/history/:scanId
 * Return full scan details for a specific scan.
 * Only accessible by the scan owner.
 */
router.get('/:scanId', async (req, res) => {
  try {
    if (!mongo.isConnected()) {
      return res.status(503).json({
        error: 'Database unavailable.',
      });
    }

    const scan = await Scan.findOne({
      scanId: req.params.scanId,
      userId: req.user.id,
    }).lean();

    if (!scan) {
      return res.status(404).json({
        error: 'Scan not found or access denied.',
      });
    }

    res.json({
      status: 'success',
      data: scan,
    });
  } catch (err) {
    console.error('[History] Fetch scan error:', err.message);
    res.status(500).json({ error: 'Failed to retrieve scan details.' });
  }
});

/**
 * DELETE /api/history/:scanId
 * Delete a specific scan from history.
 */
router.delete('/:scanId', async (req, res) => {
  try {
    if (!mongo.isConnected()) {
      return res.status(503).json({ error: 'Database unavailable.' });
    }

    const result = await Scan.deleteOne({
      scanId: req.params.scanId,
      userId: req.user.id,
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Scan not found or access denied.' });
    }

    res.json({ status: 'success', message: 'Scan deleted.' });
  } catch (err) {
    console.error('[History] Delete error:', err.message);
    res.status(500).json({ error: 'Failed to delete scan.' });
  }
});

module.exports = router;
