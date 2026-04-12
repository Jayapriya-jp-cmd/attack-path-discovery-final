// ─────────────────────────────────────────
//  Report Routes — GET /api/report
// ─────────────────────────────────────────
const { Router } = require('express');
const { getScan, getLatestScan, getAllScanIds } = require('../orchestrator');

const router = Router();

/**
 * GET /api/report
 * Returns the latest scan report in strict JSON format (Phase 11 spec).
 */
router.get('/', (req, res) => {
  const scan = getLatestScan();
  if (!scan) {
    return res.status(404).json({ error: 'No scan data available. Run a scan first.' });
  }
  res.json(toReportFormat(scan));
});

/**
 * GET /api/report/:scanId
 * Returns report for a specific scan ID.
 */
router.get('/:scanId', (req, res) => {
  const scan = getScan(req.params.scanId);
  if (!scan) {
    return res.status(404).json({ error: `Scan ${req.params.scanId} not found.` });
  }
  res.json(toReportFormat(scan));
});

/**
 * GET /api/report/list/all
 * Returns all scan IDs.
 */
router.get('/list/all', (req, res) => {
  res.json({ scans: getAllScanIds() });
});

/**
 * Convert scan result to the strict Phase 11 JSON format.
 */
function toReportFormat(scan) {
  return {
    target: scan.target,
    scanId: scan.scanId,
    scanTime: scan.scanTime,
    duration: scan.duration,
    os: scan.os,
    ports: scan.ports,
    services: scan.services,
    vulnerabilities: scan.vulnerabilities.map(v => ({
      cve: v.cve,
      description: v.description,
      severity: v.severity,
      cvss: v.cvss,
      port: v.port,
      service: v.service,
      source: v.source,
    })),
    exploits: scan.exploits.map(e => ({
      title: e.title,
      path: e.path,
      type: e.type,
      platform: e.platform,
      port: e.port,
      service: e.service,
    })),
    privEscVectors: scan.privEscVectors,
    adAnalysis: scan.adAnalysis,
    attack_paths: scan.attack_paths.map(p => ({
      id: p.id,
      name: p.name,
      steps: p.steps.map(s => ({
        stage: s.stage,
        description: s.description,
        tool: s.tool,
        confidence: s.confidence,
      })),
      risk_score: p.risk_score,
      severity: p.severity,
    })),
    summary: scan.summary,
  };
}

module.exports = router;
