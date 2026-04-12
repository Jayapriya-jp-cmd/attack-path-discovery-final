// ─────────────────────────────────────────
//  Graph Routes — GET /api/graph
// ─────────────────────────────────────────
const { Router } = require('express');
const { getScan, getLatestScan } = require('../orchestrator');
const { authMiddleware } = require('../middleware/auth');
const Scan = require('../models/Scan');
const mongo = require('../db/mongo');

const router = Router();

// All graph routes require authentication
router.use(authMiddleware);

/**
 * GET /api/graph
 * Returns the latest scan graph in Cytoscape.js-compatible format.
 */
router.get('/', async (req, res) => {
  // Try in-memory first
  const scan = getLatestScan();
  if (scan) {
    return res.json(toCytoscapeFormat(scan.graph));
  }

  // Fallback to MongoDB
  if (mongo.isConnected()) {
    try {
      const dbScan = await Scan.findOne({ userId: req.user.id })
        .sort({ createdAt: -1 })
        .select('graphData')
        .lean();

      if (dbScan && dbScan.graphData) {
        return res.json(toCytoscapeFormat(dbScan.graphData));
      }
    } catch (err) {
      console.error('[Graph] MongoDB fetch error:', err.message);
    }
  }

  return res.status(404).json({ error: 'No scan data available. Run a scan first.' });
});

/**
 * GET /api/graph/:scanId
 * Returns graph for a specific scan ID.
 */
router.get('/:scanId', async (req, res) => {
  // Try in-memory first
  const scan = getScan(req.params.scanId);
  if (scan) {
    return res.json(toCytoscapeFormat(scan.graph));
  }

  // Fallback to MongoDB
  if (mongo.isConnected()) {
    try {
      const dbScan = await Scan.findOne({
        scanId: req.params.scanId,
        userId: req.user.id,
      })
        .select('graphData')
        .lean();

      if (dbScan && dbScan.graphData) {
        return res.json(toCytoscapeFormat(dbScan.graphData));
      }
    } catch (err) {
      console.error('[Graph] MongoDB fetch error:', err.message);
    }
  }

  return res.status(404).json({ error: `Scan ${req.params.scanId} not found.` });
});

/**
 * Convert internal graph format to Cytoscape.js elements format.
 */
function toCytoscapeFormat(graph) {
  if (!graph) return { elements: { nodes: [], edges: [] } };

  const nodes = graph.nodes.map(n => ({
    data: {
      id: n.id,
      label: n.label,
      type: n.type,
      ...flattenForCytoscape(n.data),
    },
    classes: n.type.toLowerCase(),
  }));

  const edges = graph.edges.map((e, i) => ({
    data: {
      id: `edge_${i}`,
      source: e.source,
      target: e.target,
      label: e.type,
      type: e.type,
    },
  }));

  return { elements: { nodes, edges } };
}

function flattenForCytoscape(data) {
  if (!data) return {};
  const result = {};
  for (const [key, value] of Object.entries(data)) {
    if (typeof value !== 'object' || value === null) {
      result[key] = value;
    }
  }
  return result;
}

module.exports = router;
