// ─────────────────────────────────────────
//  Scan Routes — POST /api/scan
//  Returns REAL results or error. No mock data.
// ─────────────────────────────────────────
const { Router } = require('express');
const { runScan, getScan } = require('../orchestrator');
const { authMiddleware } = require('../middleware/auth');
const { scanLimiter } = require('../middleware/rateLimiter');
const Scan = require('../models/Scan');
const mongo = require('../db/mongo');

const router = Router();

/**
 * POST /api/scan
 * Body: { "target": "192.168.1.100" }
 * Starts a full scan pipeline and returns results.
 * Requires authentication. Saves result to MongoDB.
 *
 * Returns FLAT JSON per spec:
 *   { target, ports, services, exploits, attackPaths, status }
 * On error:
 *   { status: "error", message: "..." }
 */
router.post('/', authMiddleware, scanLimiter, async (req, res) => {
  const { target } = req.body;

  // STEP 1: Validate input
  if (!target || typeof target !== 'string') {
    return res.status(400).json({
      status: 'error',
      message: 'Missing or invalid "target" field. Provide an IP address or domain.',
    });
  }

  // Basic input validation — IP or domain format
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;

  if (!ipRegex.test(target) && !domainRegex.test(target) && !cidrRegex.test(target)) {
    return res.status(400).json({
      status: 'error',
      message: 'Invalid target format. Provide a valid IP address or domain name.',
    });
  }

  try {
    // Get the Socket.IO instance from the app
    const io = req.app.get('io');
    const emit = io ? (event, data) => io.emit(event, data) : () => {};

    console.log(`[API] Scan requested for: ${target} by user: ${req.user.username}`);

    // STEP 2-5: Execute the REAL pipeline
    const result = await runScan(target, emit);

    // STEP 6: Store results in MongoDB
    if (mongo.isConnected()) {
      try {
        const scanDoc = new Scan({
          userId: req.user.id,
          scanId: result.scanId,
          target: result.target,
          scanResult: {
            target: result.target,
            scanTime: result.scanTime,
            os: result.os,
          },
          attackPaths: result.attackPaths,
          graphData: result.graph,
          summary: result.summary,
          duration: result.duration,
          os: result.os,
          ports: result.ports,
          services: result.services,
          vulnerabilities: result.vulnerabilities,
          exploits: result.exploits,
          privEscVectors: result.privEscVectors,
          adAnalysis: result.adAnalysis,
        });
        await scanDoc.save();
        console.log(`[API] Scan saved to MongoDB: ${result.scanId}`);
      } catch (saveErr) {
        console.error(`[API] MongoDB save failed: ${saveErr.message}`);
        // Don't fail the scan — just log the error
      }
    }

    // STEP 7: Return FLAT response (per spec)
    res.json({
      status: 'success',
      target: result.target,
      ports: result.ports,
      services: result.services,
      exploits: result.exploits,
      attackPaths: result.attackPaths,
      vulnerabilities: result.vulnerabilities,
      privEscVectors: result.privEscVectors,
      graph: result.graph,
      summary: result.summary,
      scanId: result.scanId,
      duration: result.duration,
      os: result.os,
      timestamp: result.timestamp,
    });
  } catch (err) {
    console.error(`[API] Scan failed: ${err.message}`);
    res.status(500).json({
      status: 'error',
      message: err.message,
    });
  }
});

/**
 * GET /api/scan/:id
 * Get a specific scan result by ID.
 */
router.get('/:id', authMiddleware, async (req, res) => {
  const scan = getScan(req.params.id);
  if (!scan) {
    return res.status(404).json({
      status: 'error',
      message: 'Scan not found',
    });
  }
  res.json({ status: 'success', ...scan });
});

module.exports = router;
