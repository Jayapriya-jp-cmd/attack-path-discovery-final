// ============================================================
//  PHASE 4: PRIVILEGE ESCALATION SIMULATION — PrivEscService
//  Simulates LinPEAS output. NO real execution.
// ============================================================

const patterns = require('../data/privesc_patterns.json');

/**
 * Simulate privilege escalation analysis based on OS and services.
 * @param {object} scanResult - From nmapService
 * @param {Array} vulnerabilities - From cveService
 * @param {function} onProgress
 * @returns {object} privesc analysis
 */
function simulatePrivesc(scanResult, vulnerabilities, onProgress = () => {}) {
  onProgress('[SIMULATION] Analyzing privilege escalation vectors (LinPEAS simulation)...');

  const os = (scanResult.osInfo || '').toLowerCase();
  const isLinux = os.includes('linux') || os.includes('ubuntu') || os.includes('debian') || os.includes('centos') || !os.includes('windows');
  const isWindows = os.includes('windows');

  const results = {
    simulated: true,
    disclaimer: 'These results are SIMULATED based on OS fingerprinting and known patterns. LinPEAS was NOT executed.',
    os_type: isWindows ? 'windows' : 'linux',
    suid_binaries: [],
    misconfigurations: [],
    weak_permissions: [],
    windows_vectors: [],
    kernel_exploits: [],
    cve_based_privesc: [],
  };

  if (isLinux) {
    // Select random subset of SUID binaries (simulation)
    results.suid_binaries = selectRandom(patterns.suid_binaries, 3).map(b => ({
      ...b,
      status: 'POTENTIAL_VECTOR',
      note: '[SIMULATED] This SUID binary was found during enumeration',
    }));

    // Select misconfigurations
    results.misconfigurations = selectRandom(patterns.misconfigurations, 4).map(m => ({
      ...m,
      status: 'POTENTIAL_VECTOR',
      note: '[SIMULATED] Detected via configuration analysis',
    }));

    // Weak permissions
    results.weak_permissions = selectRandom(patterns.weak_file_permissions, 2).map(p => ({
      ...p,
      status: 'POTENTIAL_VECTOR',
      note: '[SIMULATED] File permission weakness detected',
    }));

    // Kernel exploits from CVE database
    const kernelCves = vulnerabilities.filter(v => v.privesc && v.escalates_to === 'root');
    results.kernel_exploits = kernelCves.map(c => ({
      cve: c.id,
      name: c.exploit_title || c.description.slice(0, 80),
      description: c.description,
      severity: c.severity,
      escalates_to: c.escalates_to,
      status: 'POTENTIAL_VECTOR',
    }));

    // Add Sudo privesc if sudo/common
    results.cve_based_privesc = vulnerabilities
      .filter(v => v.privesc)
      .map(v => ({
        cve: v.id,
        description: v.description,
        severity: v.severity,
        escalates_to: v.escalates_to,
        exploit_available: v.exploit_available,
        status: 'POTENTIAL_VECTOR',
      }));
  }

  if (isWindows) {
    results.windows_vectors = generateWindowsVectors(vulnerabilities);
  }

  const totalVectors =
    results.suid_binaries.length +
    results.misconfigurations.length +
    results.weak_permissions.length +
    results.windows_vectors.length +
    results.kernel_exploits.length +
    results.cve_based_privesc.length;

  onProgress(`PrivEsc simulation complete. Found ${totalVectors} potential vector(s).`);
  return results;
}

/**
 * Generate Windows-specific privilege escalation vectors.
 */
function generateWindowsVectors(vulnerabilities) {
  const vectors = [
    {
      type: 'AlwaysInstallElevated',
      description: 'AlwaysInstallElevated registry key set — install malicious MSI as SYSTEM',
      severity: 'CRITICAL',
      status: 'POTENTIAL_VECTOR',
      note: '[SIMULATED]',
    },
    {
      type: 'UnquotedServicePaths',
      description: 'Service binary path is unquoted and contains spaces — plant malicious binary',
      severity: 'HIGH',
      status: 'POTENTIAL_VECTOR',
      note: '[SIMULATED]',
    },
    {
      type: 'WeakServicePermissions',
      description: 'Authenticated users have write permission to service binary — replace for SYSTEM execution',
      severity: 'HIGH',
      status: 'POTENTIAL_VECTOR',
      note: '[SIMULATED]',
    },
    {
      type: 'TokenImpersonation',
      description: 'SeImpersonatePrivilege enabled — use PrintSpoofer or JuicyPotato for SYSTEM',
      severity: 'CRITICAL',
      status: 'POTENTIAL_VECTOR',
      note: '[SIMULATED]',
    },
    {
      type: 'AutoRunRegistryKeys',
      description: 'Writable autorun registry keys found — persist and escalate on next login',
      severity: 'MEDIUM',
      status: 'POTENTIAL_VECTOR',
      note: '[SIMULATED]',
    },
  ];

  // Add any CVE-based Windows privesc
  const winCves = vulnerabilities.filter(
    v => v.privesc && (v.escalates_to === 'SYSTEM' || v.escalates_to === 'Domain Admin')
  );
  for (const c of winCves) {
    vectors.push({
      type: 'CVE',
      cve: c.id,
      description: c.description,
      severity: c.severity,
      escalates_to: c.escalates_to,
      status: 'POTENTIAL_VECTOR',
      note: '[SIMULATED via CVE DB]',
    });
  }

  return vectors;
}

/**
 * Randomly select N items from array (for simulation variety).
 */
function selectRandom(arr, n) {
  const shuffled = [...arr].sort(() => 0.5 - Math.random());
  return shuffled.slice(0, n);
}

module.exports = { simulatePrivesc };
