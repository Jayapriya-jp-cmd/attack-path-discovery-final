// ═══════════════════════════════════════════════════════════
//  Vulnerability Mapper — CVE correlation from real scan data
//  Uses local CVE database to match REAL detected services.
//  NO mock delays. Matches are based on real Nmap output only.
// ═══════════════════════════════════════════════════════════
const path = require('path');
const fs = require('fs');

// Load local CVE database (this is a reference database, not hardcoded results)
const CVE_DB_PATH = path.join(__dirname, '..', 'data', 'cve-database.json');
let cveDatabase = [];

try {
  cveDatabase = JSON.parse(fs.readFileSync(CVE_DB_PATH, 'utf8'));
  console.log(`[VulnMapper] Loaded ${cveDatabase.length} CVEs from local database`);
} catch (err) {
  console.warn('[VulnMapper] Could not load CVE database:', err.message);
  console.warn('[VulnMapper] Vulnerability mapping will return empty results');
}

/**
 * Map REAL detected services to known vulnerabilities.
 * Only matches CVEs against services that were ACTUALLY detected by Nmap.
 *
 * @param {Array} ports - Port objects from REAL Nmap scan output
 * @returns {Array} Matched vulnerabilities (only for detected services)
 */
async function mapVulnerabilities(ports) {
  console.log(`\n[VulnMapper] ══════════════════════════════════════`);
  console.log(`[VulnMapper] MAPPING REAL SERVICES TO KNOWN CVEs`);
  console.log(`[VulnMapper] Services to check: ${ports.length}`);
  console.log(`[VulnMapper] CVE database size: ${cveDatabase.length}`);
  console.log(`[VulnMapper] ══════════════════════════════════════`);

  if (cveDatabase.length === 0) {
    console.warn('[VulnMapper] CVE database empty — no matching possible');
    return [];
  }

  const vulnerabilities = [];

  for (const port of ports) {
    const svc = port.service;
    if (!svc || !svc.name || svc.name === 'unknown') {
      console.log(`[VulnMapper] Skipping port ${port.number}: no service identified`);
      continue;
    }

    console.log(`[VulnMapper] Checking port ${port.number}: ${svc.product || svc.name} ${svc.version || '(no version)'}`);

    // Match against CVE database using REAL detected service info
    const matches = cveDatabase.filter(cve => {
      const svcNameMatch =
        cve.affected_service.toLowerCase() === svc.name.toLowerCase() ||
        (svc.product && cve.affected_product &&
          svc.product.toLowerCase().includes(cve.affected_product.toLowerCase()));

      if (!svcNameMatch) return false;

      // Version range check (only if we have version info from Nmap)
      if (cve.affected_versions && svc.version) {
        return cve.affected_versions.some(v => versionInRange(svc.version, v));
      }

      // If CVE has no version constraint, match on service name only
      return true;
    });

    console.log(`[VulnMapper]   → ${matches.length} CVE match(es)`);

    for (const cve of matches) {
      vulnerabilities.push({
        cve: cve.id,
        description: cve.description,
        severity: cve.severity,
        cvss: cve.cvss,
        port: port.number,
        service: svc.name,
        serviceVersion: svc.version,
        product: svc.product || svc.name,
        verified: false,
        source: 'local-cve-db',
        matchBasis: `Matched ${svc.product || svc.name} ${svc.version || ''} from Nmap output`,
      });
    }
  }

  console.log(`[VulnMapper] ✓ Total: ${vulnerabilities.length} potential vulnerabilities`);
  return vulnerabilities;
}

/**
 * Simple version range check.
 * Format: "<=X.Y.Z" or "X.Y.Z"
 */
function versionInRange(detected, rangeStr) {
  if (!detected || !rangeStr) return false;

  const cleanRange = rangeStr.replace(/^<=?/, '');
  const detParts = detected.split('.').map(Number);
  const rngParts = cleanRange.split('.').map(Number);

  for (let i = 0; i < Math.max(detParts.length, rngParts.length); i++) {
    const d = detParts[i] || 0;
    const r = rngParts[i] || 0;
    if (d < r) return true;
    if (d > r) return false;
  }
  return true; // equal
}

module.exports = { mapVulnerabilities };
