// ============================================================
//  PHASE 5: ACTIVE DIRECTORY ANALYSIS — ADService
//  Uses fully simulated BloodHound dataset.
// ============================================================

const bhData = require('../data/bloodhound_sim.json');

/**
 * Analyze Active Directory using simulated BloodHound data.
 * @param {object} scanResult - From nmapService
 * @param {Array} vulnerabilities - From cveService
 * @param {function} onProgress
 * @returns {object|null} AD analysis or null if not applicable
 */
function analyzeActiveDirectory(scanResult, vulnerabilities, onProgress = () => {}) {
  const isWindows = detectWindows(scanResult);
  const hasADPorts = detectADPorts(scanResult);

  if (!isWindows && !hasADPorts) {
    onProgress('No Windows/Active Directory environment detected. Skipping AD analysis.');
    return null;
  }

  onProgress('[SIMULATED] Active Directory / BloodHound analysis starting...');
  onProgress('Loading simulated domain data for: ' + bhData.domain.name);

  // Find kerberoastable accounts
  const kerberoastable = bhData.users.filter(u => u.kerberoastable);
  const asreproastable = bhData.users.filter(u => u.asreproastable);
  const highValueTargets = bhData.users.filter(u => u.adminCount);
  const stalePasswords = bhData.users.filter(u => isStalePassword(u.passwordLastSet));

  // Lateral movement paths
  const lateralPaths = computeLateralMovement();

  // Check for Zerologon applicability
  const hasZerologon = vulnerabilities.some(v => v.id === 'CVE-2020-1472');

  const analysis = {
    simulated: true,
    disclaimer: '[SIMULATED] This AD analysis uses pre-built sample data — not real domain data.',
    domain: bhData.domain,
    statistics: {
      total_users: bhData.users.length,
      total_computers: bhData.computers.length,
      total_groups: bhData.groups.length,
      kerberoastable_accounts: kerberoastable.length,
      asreproastable_accounts: asreproastable.length,
      high_value_targets: highValueTargets.length,
      stale_passwords: stalePasswords.length,
    },
    kerberoastable_accounts: kerberoastable.map(u => ({
      username: u.name,
      spn: u.spn,
      password_age_days: getDaysSince(u.passwordLastSet),
      risk: getDaysSince(u.passwordLastSet) > 365 ? 'HIGH' : 'MEDIUM',
    })),
    asreproastable_accounts: asreproastable.map(u => ({
      username: u.name,
      password_age_days: getDaysSince(u.passwordLastSet),
      risk: getDaysSince(u.passwordLastSet) > 180 ? 'HIGH' : 'MEDIUM',
    })),
    high_value_targets: highValueTargets.map(u => ({
      username: u.name,
      last_logon: u.lastLogon,
      groups: u.memberOf,
    })),
    stale_passwords: stalePasswords.map(u => ({
      username: u.name,
      password_last_set: u.passwordLastSet,
      days_since_change: getDaysSince(u.passwordLastSet),
    })),
    lateral_movement_paths: lateralPaths,
    attack_paths: bhData.attack_paths,
    acls: bhData.acls,
    zerologon_applicable: hasZerologon,
    computers: bhData.computers.map(c => ({
      name: c.name,
      os: c.os,
      role: c.role,
      local_admins: c.localAdmins?.length || 0,
      active_sessions: c.sessions?.length || 0,
    })),
  };

  onProgress(`AD analysis complete. Found ${kerberoastable.length} Kerberoastable, ${asreproastable.length} AS-REP Roastable accounts.`);
  return analysis;
}

/**
 * Compute lateral movement paths from group/computer relationships.
 */
function computeLateralMovement() {
  const paths = [];

  for (const group of bhData.groups) {
    if (group.adminTo) {
      for (const computerId of group.adminTo) {
        const computer = bhData.computers.find(c => c.id === computerId);
        const members = group.members.map(uid => bhData.users.find(u => u.id === uid)?.name).filter(Boolean);
        if (computer && members.length) {
          paths.push({
            type: 'AdminTo',
            from: members,
            via_group: group.name,
            to: computer.name,
            description: `${members.join(', ')} → [${group.name}] → Admin on ${computer.name}`,
          });
        }
      }
    }
    if (group.canRDP) {
      for (const computerId of group.canRDP) {
        const computer = bhData.computers.find(c => c.id === computerId);
        const members = group.members.map(uid => bhData.users.find(u => u.id === uid)?.name).filter(Boolean);
        if (computer && members.length) {
          paths.push({
            type: 'CanRDP',
            from: members,
            via_group: group.name,
            to: computer.name,
            description: `${members.join(', ')} → [${group.name}] → RDP to ${computer.name}`,
          });
        }
      }
    }
  }

  return paths;
}

/**
 * Detect Windows/AD environment from scan.
 */
function detectWindows(scanResult) {
  const os = (scanResult.osInfo || '').toLowerCase();
  return os.includes('windows') || os.includes('server');
}

/**
 * Detect AD-related ports in scan.
 */
function detectADPorts(scanResult) {
  const adPorts = [88, 389, 445, 464, 636, 3268, 3269]; // Kerberos, LDAP, SMB
  return scanResult.ports?.some(p => adPorts.includes(p.port)) || false;
}

function isStalePassword(dateStr) {
  if (!dateStr || dateStr === 'Never') return true;
  return getDaysSince(dateStr) > 180;
}

function getDaysSince(dateStr) {
  if (!dateStr || dateStr === 'Never') return 9999;
  const d = new Date(dateStr);
  return Math.floor((Date.now() - d.getTime()) / (1000 * 60 * 60 * 24));
}

module.exports = { analyzeActiveDirectory };
