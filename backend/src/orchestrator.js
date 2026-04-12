// ─────────────────────────────────────────
//  Scan Orchestrator — Pipeline coordinator
//  REAL EXECUTION ONLY. NO MOCK DATA.
// ─────────────────────────────────────────
const { v4: uuidv4 } = require('uuid');
const { runNmapScan } = require('./engines/recon');
const { mapVulnerabilities } = require('./engines/vulnMapper');
const { searchExploits } = require('./engines/exploitIntel');
const { simulatePrivEsc } = require('./engines/privEscSimulator');
const { analyzeAD } = require('./engines/adAnalyzer');
const { correlate } = require('./engines/correlationEngine');
const { generatePaths } = require('./engines/pathGenerator');

// In-memory store for scan results
const scanStore = new Map();

/**
 * Run the full scan pipeline for a target.
 * Every step uses REAL tool execution. No mock data. No fallbacks.
 *
 * @param {string} target - IP or domain to scan
 * @param {function} emit - Socket.IO emit function for progress updates
 * @returns {Object} full scan results
 */
async function runScan(target, emit = () => {}) {
  const scanId = uuidv4();
  const startTime = Date.now();

  console.log(`\n${'═'.repeat(60)}`);
  console.log(`  SCAN STARTED: ${target} [${scanId}]`);
  console.log(`${'═'.repeat(60)}\n`);

  const progress = (phase, pct, message) => {
    emit('scan:progress', { scanId, phase, progress: pct, message });
    console.log(`  [${pct}%] ${phase}: ${message}`);
  };

  try {
    // ── Phase 1: Reconnaissance (REAL Nmap) ──
    progress('Reconnaissance', 10, 'Running Nmap...');
    const scanResult = await runNmapScan(target);
    progress('Reconnaissance', 25, `Found ${scanResult.ports.length} open ports`);

    // ── Phase 2: Vulnerability Mapping (CVE database lookup) ──
    progress('Vulnerability Mapping', 30, 'Mapping services to known CVEs...');
    const vulnerabilities = await mapVulnerabilities(scanResult.ports);
    progress('Vulnerability Mapping', 45, `Found ${vulnerabilities.length} vulnerabilities`);

    // ── Phase 3: Exploit Intelligence (REAL Searchsploit) ──
    progress('Exploit Intelligence', 50, 'Running Searchsploit...');
    const exploits = await searchExploits(scanResult.ports);
    progress('Exploit Intelligence', 60, `Found ${exploits.length} potential exploits`);

    // ── Phase 4: Privilege Escalation Analysis ──
    progress('Privilege Escalation', 65, 'Analyzing privilege escalation vectors...');
    const privEscVectors = await simulatePrivEsc(scanResult);
    progress('Privilege Escalation', 75, `Identified ${privEscVectors.length} vectors`);

    // ── Phase 5: Active Directory Analysis ──
    progress('Active Directory', 78, 'Checking for AD indicators...');
    const adAnalysis = await analyzeAD(scanResult);
    progress('Active Directory', 82, adAnalysis ? 'AD analysis complete' : 'No AD environment detected');

    // ── Phase 6: Correlation (builds graph from REAL data) ──
    progress('Correlation', 85, 'Correlating findings into attack chains...');
    // FIX: Pass data with the correct keys that correlate() expects
    const correlationInput = {
      recon: scanResult,
      vulns: vulnerabilities,
      exploits,
      privEsc: privEscVectors,
      ad: adAnalysis,
    };
    const graph = correlate(correlationInput);
    progress('Correlation', 90, `Built graph: ${graph.nodes.length} nodes, ${graph.edges.length} edges`);

    // ── Phase 7: Attack Path Generation (data-driven ONLY) ──
    progress('Path Generation', 92, 'Generating attack paths...');
    // FIX: Pass (graph, scanId) — the correct signature for generatePaths
    const attackPaths = await generatePaths(graph, scanId);
    progress('Path Generation', 98, `Generated ${attackPaths.length} attack paths`);

    // ── Build final result (flat format per spec) ──
    const result = {
      scanId,
      target: scanResult.target,
      scanTime: scanResult.scanTime,
      duration: `${((Date.now() - startTime) / 1000).toFixed(1)}s`,
      os: scanResult.os,
      ports: scanResult.ports.map(p => p.number),
      services: scanResult.ports.map(p => ({
        port: p.number,
        name: p.service.name,
        version: `${p.service.product || ''} ${p.service.version || ''}`.trim() || 'unknown',
      })),
      vulnerabilities,
      exploits,
      privEscVectors,
      adAnalysis,
      graph,
      attackPaths,
      summary: {
        totalPorts: scanResult.ports.length,
        totalVulnerabilities: vulnerabilities.length,
        totalExploits: exploits.length,
        totalPrivEscVectors: privEscVectors.length,
        totalAttackPaths: attackPaths.length,
        highestRisk: attackPaths.length > 0
          ? Math.max(...attackPaths.map(p => p.riskScore || 0))
          : 0,
        overallSeverity: getOverallSeverity(attackPaths),
      },
      status: 'success',
      timestamp: new Date().toISOString(),
    };

    // Store result in memory
    scanStore.set(scanId, result);

    progress('Complete', 100, 'Scan complete!');
    emit('scan:complete', { scanId });

    console.log(`\n${'═'.repeat(60)}`);
    console.log(`  SCAN COMPLETE: ${attackPaths.length} paths, highest risk: ${result.summary.highestRisk}`);
    console.log(`${'═'.repeat(60)}\n`);

    return result;

  } catch (err) {
    console.error(`[Orchestrator] Scan failed: ${err.message}`);
    emit('scan:error', { scanId, error: err.message });
    throw err;
  }
}

function getOverallSeverity(paths) {
  if (paths.length === 0) return 'Info';
  const highest = Math.max(...paths.map(p => p.riskScore || 0));
  if (highest >= 9) return 'Critical';
  if (highest >= 7) return 'High';
  if (highest >= 4) return 'Medium';
  return 'Low';
}

/**
 * Get stored scan result by ID.
 */
function getScan(scanId) {
  return scanStore.get(scanId);
}

/**
 * Get the latest scan result.
 */
function getLatestScan() {
  const entries = Array.from(scanStore.entries());
  if (entries.length === 0) return null;
  return entries[entries.length - 1][1];
}

/**
 * Get all scan IDs.
 */
function getAllScanIds() {
  return Array.from(scanStore.keys());
}

module.exports = { runScan, getScan, getLatestScan, getAllScanIds };
