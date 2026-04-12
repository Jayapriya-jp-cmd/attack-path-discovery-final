// ─────────────────────────────────────────
//  Active Directory Analyzer (Simulated)
// ─────────────────────────────────────────
const path = require('path');
const fs = require('fs');

const AD_DATA_PATH = path.join(__dirname, '..', 'data', 'ad-simulation.json');
let adData = null;

try {
  adData = JSON.parse(fs.readFileSync(AD_DATA_PATH, 'utf8'));
} catch {
  // AD data is optional
}

/**
 * Detect if the target has Active Directory indicators.
 * Checks for typical AD ports: 88 (Kerberos), 389 (LDAP), 636 (LDAPS), 445 (SMB).
 */
function isADEnvironment(scanResult) {
  const adPorts = [88, 389, 636, 445];
  const openPorts = scanResult.ports.map(p => p.number);
  const matchCount = adPorts.filter(p => openPorts.includes(p)).length;
  return matchCount >= 2;
}

/**
 * Analyze Active Directory relationships and potential attack paths.
 * Uses simulated BloodHound-style dataset.
 *
 * @param {Object} scanResult - Recon scan result
 * @returns {Object|null} AD analysis or null if not applicable
 */
async function analyzeAD(scanResult) {
  if (!isADEnvironment(scanResult)) {
    console.log('[AD] No Active Directory indicators detected — skipping');
    return null;
  }

  console.log('[AD] Active Directory indicators detected — analyzing...');
  await new Promise(r => setTimeout(r, 400));

  if (!adData) {
    console.log('[AD] No AD simulation data available');
    return null;
  }

  // Extract lateral movement paths
  const lateralPaths = [];

  // Find Kerberoastable accounts → service account compromise
  const kerberoastable = adData.users.filter(u => u.kerberoastable);
  for (const user of kerberoastable) {
    lateralPaths.push({
      type: 'Kerberoasting',
      from: 'Domain User',
      to: user.name,
      description: `${user.name} has an SPN set — Kerberos TGS can be requested and cracked offline`,
      severity: 'High',
      confidence: 'Medium',
    });
  }

  // Find delegation abuse paths
  const delegationUsers = adData.users.filter(u => u.unconstrained_delegation);
  for (const user of delegationUsers) {
    lateralPaths.push({
      type: 'Unconstrained Delegation',
      from: user.name,
      to: 'Domain Controller',
      description: `${user.name} has unconstrained delegation — can impersonate any user`,
      severity: 'Critical',
      confidence: 'Medium',
    });
  }

  // Find group membership escalation
  const adminPaths = adData.groups
    .filter(g => g.name === 'Domain Admins')
    .flatMap(g => g.members.map(m => ({
      type: 'Group Membership',
      from: m,
      to: 'Domain Admin',
      description: `${m} is a member of Domain Admins`,
      severity: 'Critical',
      confidence: 'High',
    })));

  lateralPaths.push(...adminPaths);

  return {
    domain: adData.domain,
    users: adData.users.map(u => ({
      name: u.name,
      enabled: u.enabled,
      kerberoastable: u.kerberoastable || false,
      adminCount: u.admin_count || false,
    })),
    groups: adData.groups.map(g => ({
      name: g.name,
      memberCount: g.members.length,
    })),
    computers: adData.computers || [],
    lateralPaths,
  };
}

module.exports = { analyzeAD, isADEnvironment };
