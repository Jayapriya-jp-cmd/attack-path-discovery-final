// ============================================================
//  PHASE 6: CORRELATION ENGINE
//  Links ports → services → CVEs → exploits into attack chains.
// ============================================================

/**
 * Correlate all scan findings into logical attack chains.
 * @param {object} scanResult
 * @param {Array} vulnerabilities
 * @param {Array} exploits
 * @param {object} privesc
 * @param {object|null} adAnalysis
 * @param {function} onProgress
 * @returns {Array} correlatedChains
 */
function correlate(scanResult, vulnerabilities, exploits, privesc, adAnalysis, onProgress = () => {}) {
  onProgress('Running correlation engine — linking findings into attack chains...');

  const chains = [];

  // ─── 1. Network Service Chains ───────────────────────────
  for (const svc of scanResult.services) {
    const svcVulns = vulnerabilities.filter(v => v.affectedPort === svc.port);
    const svcExploits = exploits.filter(e => e.port === svc.port);

    for (const vuln of svcVulns) {
      const matchedExploits = svcExploits.filter(e =>
        e.cve_reference?.includes(vuln.id) || isExploitRelated(e, vuln)
      );

      const chain = {
        id: `CHAIN-${svc.port}-${vuln.id}`,
        type: 'NETWORK',
        confirmed: true,
        nodes: [
          {
            stage: 'TARGET',
            label: `Target: ${scanResult.target}`,
            type: 'Target',
            data: { ip: scanResult.target, os: scanResult.osInfo },
          },
          {
            stage: 'PORT',
            label: `Port ${svc.port}/${svc.protocol}`,
            type: 'Port',
            data: { port: svc.port, protocol: svc.protocol, state: 'open' },
          },
          {
            stage: 'SERVICE',
            label: `${svc.product || svc.name} ${svc.version || ''}`.trim(),
            type: 'Service',
            data: { name: svc.name, product: svc.product, version: svc.version, banner: svc.fullVersion },
          },
          {
            stage: 'VULNERABILITY',
            label: vuln.id,
            type: 'Vulnerability',
            data: { cve: vuln.id, cvss: vuln.cvss_v3, severity: vuln.severity, description: vuln.description },
          },
          ...(matchedExploits.length > 0 ? [{
            stage: 'EXPLOIT',
            label: matchedExploits[0].title,
            type: 'Exploit',
            data: { title: matchedExploits[0].title, path: matchedExploits[0].path, type: matchedExploits[0].type },
          }] : []),
          {
            stage: 'ACCESS',
            label: vuln.initial_access ? 'Initial Access (Remote)' : 'Post-Auth Access',
            type: 'AccessLevel',
            data: {
              level: vuln.initial_access ? 'initial_access' : 'post_auth',
              authenticated: !vuln.initial_access,
              remote: vuln.attack_vector === 'NETWORK',
            },
          },
        ],
        cvss: vuln.cvss_v3,
        severity: vuln.severity,
        exploit_available: matchedExploits.length > 0 || vuln.exploit_available,
        initial_access: vuln.initial_access,
        privesc_possible: vuln.privesc || false,
        escalates_to: vuln.escalates_to || null,
        tags: vuln.tags || [],
      };

      // Add privesc node if applicable
      if (vuln.privesc || (privesc && privesc.cve_based_privesc?.some(p => p.cve === vuln.id))) {
        chain.nodes.push({
          stage: 'PRIVILEGE_ESCALATION',
          label: `Escalate to ${vuln.escalates_to || 'root'}`,
          type: 'AccessLevel',
          data: { level: 'privileged', escalates_to: vuln.escalates_to || 'root' },
        });
      }

      chains.push(chain);
    }

    // Services with no CVE but known-insecure (Telnet, SNMP, etc.)
    if (svcVulns.length === 0 && isInherentlyInsecure(svc)) {
      chains.push(buildInsecureServiceChain(svc, scanResult));
    }
  }

  // ─── 2. PrivEsc-Only Chains (post initial access) ────────
  if (privesc) {
    for (const suid of (privesc.suid_binaries || [])) {
      chains.push({
        id: `CHAIN-PRIVESC-SUID-${suid.binary.replace(/\//g, '-')}`,
        type: 'PRIVILEGE_ESCALATION',
        confirmed: false, // simulated
        simulated: true,
        nodes: [
          { stage: 'ACCESS', label: 'Low-Privilege Shell', type: 'AccessLevel', data: { level: 'user' } },
          { stage: 'PRIVILEGE_ESCALATION', label: `SUID: ${suid.binary}`, type: 'Vulnerability', data: suid },
          { stage: 'ACCESS', label: 'Root Shell', type: 'AccessLevel', data: { level: 'root' } },
        ],
        cvss: 7.8,
        severity: suid.severity,
        exploit_available: true,
        initial_access: false,
        privesc_possible: true,
        escalates_to: 'root',
        tags: ['privesc', 'suid', 'local'],
      });
    }
  }

  // ─── 3. AD Attack Paths ───────────────────────────────────
  if (adAnalysis) {
    for (const path of (adAnalysis.attack_paths || [])) {
      chains.push({
        id: `CHAIN-AD-${path.id}`,
        type: 'ACTIVE_DIRECTORY',
        confirmed: false,
        simulated: true,
        adPath: path,
        nodes: path.steps.map((step, i) => ({
          stage: i === 0 ? 'INITIAL_ACCESS' : (i === path.steps.length - 1 ? 'DOMAIN_COMPROMISE' : 'LATERAL_MOVEMENT'),
          label: step.action,
          type: 'ADNode',
          data: step,
        })),
        cvss: path.severity === 'CRITICAL' ? 10.0 : 8.5,
        severity: path.severity,
        exploit_available: true,
        initial_access: false,
        privesc_possible: true,
        escalates_to: 'Domain Admin',
        tags: ['active-directory', 'lateral-movement'],
      });
    }
  }

  onProgress(`Correlation complete. Generated ${chains.length} attack chain(s).`);
  return chains;
}

function isExploitRelated(exploit, vuln) {
  const title = (exploit.title || '').toLowerCase();
  const desc = (vuln.description || '').toLowerCase();
  const cveId = (vuln.id || '').toLowerCase().replace('-', '').replace('cve', '');
  return title.includes(cveId) || desc.includes(cveId);
}

function isInherentlyInsecure(svc) {
  const insecure = ['telnet', 'ftp', 'snmp', 'rpc', 'rlogin', 'rsh'];
  return insecure.some(s => (svc.name || '').toLowerCase().includes(s));
}

function buildInsecureServiceChain(svc, scanResult) {
  const descriptions = {
    telnet: 'Cleartext credential transmission — trivial interception via MITM',
    ftp: 'FTP uses cleartext authentication — credentials visible on network',
    snmp: 'SNMP with default community strings allows unauthenticated device access',
  };

  const label = (svc.name || '').toLowerCase();
  const desc = Object.entries(descriptions).find(([k]) => label.includes(k));

  return {
    id: `CHAIN-INSECURE-${svc.port}`,
    type: 'INSECURE_SERVICE',
    confirmed: true,
    simulated: false,
    nodes: [
      { stage: 'TARGET', label: scanResult.target, type: 'Target', data: { ip: scanResult.target } },
      { stage: 'PORT', label: `Port ${svc.port}`, type: 'Port', data: { port: svc.port } },
      { stage: 'SERVICE', label: svc.name, type: 'Service', data: svc },
      { stage: 'VULNERABILITY', label: 'Insecure Protocol', type: 'Vulnerability', data: { description: desc?.[1] || 'Insecure protocol in use' } },
      { stage: 'ACCESS', label: 'Credential Capture / MITM', type: 'AccessLevel', data: { level: 'credential_theft' } },
    ],
    cvss: 7.0,
    severity: 'HIGH',
    exploit_available: true,
    initial_access: false,
    tags: ['insecure-protocol', 'cleartext'],
  };
}

module.exports = { correlate };
