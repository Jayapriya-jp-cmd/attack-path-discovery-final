// ============================================================
//  PHASE 7: ATTACK PATH GENERATOR
//  Converts correlation chains into ranked, structured paths.
// ============================================================

const { v4: uuidv4 } = require('uuid');

const STAGE_TOOLS = {
  RECONNAISSANCE: 'Nmap',
  PORT: 'Nmap',
  SERVICE: 'Nmap / Banner Grabbing',
  VULNERABILITY: 'CVE Database / NVD',
  EXPLOIT: 'Searchsploit / Metasploit (simulated)',
  ACCESS: 'Exploit Framework (simulated)',
  PRIVILEGE_ESCALATION: 'LinPEAS / GTFOBins (simulated)',
  LATERAL_MOVEMENT: 'BloodHound / CrackMapExec (simulated)',
  ACTIVE_DIRECTORY: 'BloodHound / Impacket (simulated)',
  DOMAIN_COMPROMISE: 'Mimikatz / DCSync (simulated)',
  TARGET: 'Nmap',
};

/**
 * Generate ranked attack paths from correlated chains.
 * @param {Array} chains - From correlationEngine
 * @param {object} scanResult
 * @param {function} onProgress
 * @returns {Array} ranked attack paths
 */
function generateAttackPaths(chains, scanResult, onProgress = () => {}) {
  onProgress('Generating ranked attack paths...');

  const networkChains = chains.filter(c => c.type === 'NETWORK' || c.type === 'INSECURE_SERVICE');
  const privescChains = chains.filter(c => c.type === 'PRIVILEGE_ESCALATION');
  const adChains = chains.filter(c => c.type === 'ACTIVE_DIRECTORY');

  const paths = [];

  // ─── Full Attack Paths (Initial Access + PrivEsc) ─────────
  for (const net of networkChains) {
    if (!net.initial_access) continue;

    const basePath = buildBasePath(net, scanResult);

    // Simple initial access path
    paths.push(basePath);

    // Chained path with privesc (if available)
    if (privescChains.length > 0) {
      const bestPrivesc = privescChains.sort((a, b) => rankScore(b) - rankScore(a))[0];
      paths.push(buildChainedPath(net, bestPrivesc, scanResult));
    }
  }

  // ─── Post-Auth / Weak Credential Paths ───────────────────
  const postAuthChains = networkChains.filter(c => !c.initial_access && c.exploit_available);
  for (const pa of postAuthChains.slice(0, 3)) {
    paths.push(buildPostAuthPath(pa, scanResult));
  }

  // ─── PrivEsc-Only Paths ────────────────────────────────────
  for (const priv of privescChains.slice(0, 3)) {
    paths.push(buildPrivescPath(priv, scanResult));
  }

  // ─── AD Paths ─────────────────────────────────────────────
  for (const ad of adChains) {
    paths.push(buildADPath(ad, scanResult));
  }

  // Deduplicate and rank
  const ranked = deduplicateAndRank(paths);

  onProgress(`Attack path generation complete. Generated ${ranked.length} path(s).`);
  return ranked;
}

/**
 * Build a basic initial-access attack path from a chain.
 */
function buildBasePath(chain, scanResult) {
  const steps = [];

  steps.push({
    stage: 'RECONNAISSANCE',
    description: `Nmap scan identified ${chain.nodes.find(n => n.stage === 'SERVICE')?.label || 'service'} on port ${chain.nodes.find(n => n.stage === 'PORT')?.data?.port}`,
    tool: 'Nmap (-sC -sV -A -T4)',
    confidence: 'HIGH',
    finding: { type: 'open_port', port: chain.nodes.find(n => n.stage === 'PORT')?.data?.port },
    verified: true,
  });

  const vulnNode = chain.nodes.find(n => n.stage === 'VULNERABILITY');
  if (vulnNode) {
    steps.push({
      stage: 'VULNERABILITY_IDENTIFICATION',
      description: `${vulnNode.data?.cve || 'Vulnerability'} identified: ${(vulnNode.data?.description || '').slice(0, 100)}...`,
      tool: 'CVE Database / NVD Lookup',
      confidence: chain.confirmed ? 'HIGH' : 'MEDIUM',
      finding: { cve: vulnNode.data?.cve, cvss: vulnNode.data?.cvss, severity: vulnNode.data?.severity },
      verified: chain.confirmed,
    });
  }

  const exploitNode = chain.nodes.find(n => n.stage === 'EXPLOIT');
  if (exploitNode || chain.exploit_available) {
    steps.push({
      stage: 'EXPLOIT_AVAILABLE',
      description: `Public exploit available: ${exploitNode?.label || 'See CVE entry'}`,
      tool: 'Searchsploit / Exploit-DB',
      confidence: exploitNode ? 'HIGH' : 'MEDIUM',
      finding: { title: exploitNode?.label, path: exploitNode?.data?.path },
      verified: !!exploitNode,
    });
  }

  steps.push({
    stage: 'INITIAL_ACCESS',
    description: `[SIMULATED] Deploy exploit to gain initial foothold on ${scanResult.target}`,
    tool: 'Metasploit / Manual Exploit (simulated)',
    confidence: computeConfidence(chain),
    finding: { access_level: 'user', remote: true },
    verified: false,
    simulated: true,
  });

  return {
    id: uuidv4(),
    chain_id: chain.id,
    name: buildPathName(chain, 'initial_access'),
    type: 'INITIAL_ACCESS',
    steps,
    risk_score: computeRiskScore(chain),
    severity: chain.severity,
    cvss: chain.cvss,
    confidence: computeConfidence(chain),
    exploit_available: chain.exploit_available,
    tags: chain.tags,
    target: scanResult.target,
    simulated_steps: steps.filter(s => s.simulated).length,
  };
}

/**
 * Build a full chained path: Initial Access → PrivEsc.
 */
function buildChainedPath(netChain, privChain, scanResult) {
  const base = buildBasePath(netChain, scanResult);
  const privNode = privChain.nodes.find(n => n.stage === 'PRIVILEGE_ESCALATION');

  base.steps.push({
    stage: 'POST_EXPLOITATION',
    description: '[SIMULATED] Enumerate local system for privilege escalation vectors (LinPEAS simulation)',
    tool: 'LinPEAS (simulated)',
    confidence: 'MEDIUM',
    finding: { vectors_found: privChain.nodes.length },
    verified: false,
    simulated: true,
  });

  base.steps.push({
    stage: 'PRIVILEGE_ESCALATION',
    description: `[SIMULATED] Exploit ${privNode?.label || 'privesc vector'} to escalate to ${privChain.escalates_to || 'root'}`,
    tool: 'GTFOBins / PwnKit / Custom Exploit (simulated)',
    confidence: 'MEDIUM',
    finding: { escalates_to: privChain.escalates_to, vector: privNode?.data },
    verified: false,
    simulated: true,
  });

  base.steps.push({
    stage: 'FULL_COMPROMISE',
    description: `[SIMULATED] ${privChain.escalates_to || 'root'} level access achieved on ${scanResult.target}`,
    tool: 'N/A',
    confidence: 'MEDIUM',
    finding: { access_level: privChain.escalates_to || 'root' },
    verified: false,
    simulated: true,
  });

  return {
    ...base,
    id: uuidv4(),
    name: buildPathName(netChain, 'full_compromise'),
    type: 'FULL_COMPROMISE',
    risk_score: Math.min(10, (base.risk_score || 7) + 1.5),
    cvss: Math.min(10, (netChain.cvss || 7) + 0.5),
    tags: [...(base.tags || []), 'privesc', 'full-compromise'],
  };
}

/**
 * Build a post-auth / weak credential path.
 */
function buildPostAuthPath(chain, scanResult) {
  const svcNode = chain.nodes.find(n => n.stage === 'SERVICE');
  const portNode = chain.nodes.find(n => n.stage === 'PORT');

  return {
    id: uuidv4(),
    chain_id: chain.id,
    name: `Weak/Default Credentials → ${svcNode?.label || 'Service'} (Port ${portNode?.data?.port})`,
    type: 'WEAK_CREDENTIALS',
    steps: [
      {
        stage: 'RECONNAISSANCE',
        description: `Service ${svcNode?.label || chain.id} identified on port ${portNode?.data?.port}`,
        tool: 'Nmap',
        confidence: 'HIGH',
        finding: { port: portNode?.data?.port },
        verified: true,
      },
      {
        stage: 'CREDENTIAL_ATTACK',
        description: `[SIMULATED] Brute force / default credential attempt against ${svcNode?.label}`,
        tool: 'Hydra / Medusa (simulated)',
        confidence: 'MEDIUM',
        finding: { method: 'brute_force_or_default_creds' },
        verified: false,
        simulated: true,
      },
      {
        stage: 'AUTHENTICATED_ACCESS',
        description: `[SIMULATED] Authenticated access to service with weak/default credentials`,
        tool: 'Manual/Hydra',
        confidence: 'MEDIUM',
        finding: { access_type: 'authenticated' },
        verified: false,
        simulated: true,
      },
    ],
    risk_score: computeRiskScore(chain) - 1,
    severity: 'HIGH',
    cvss: chain.cvss || 7.0,
    confidence: 'MEDIUM',
    exploit_available: true,
    tags: [...(chain.tags || []), 'weak-credentials', 'brute-force'],
    target: scanResult.target,
    simulated_steps: 2,
  };
}

/**
 * Build a local privilege escalation path.
 */
function buildPrivescPath(chain, scanResult) {
  const privNode = chain.nodes.find(n => n.stage === 'PRIVILEGE_ESCALATION');
  return {
    id: uuidv4(),
    chain_id: chain.id,
    name: `Local PrivEsc: ${privNode?.label || 'Unknown Vector'} → root`,
    type: 'PRIVILEGE_ESCALATION',
    steps: chain.nodes.map(n => ({
      stage: n.stage,
      description: `[SIMULATED] ${n.label}: ${JSON.stringify(n.data).slice(0, 80)}`,
      tool: STAGE_TOOLS[n.stage] || 'Unknown',
      confidence: 'MEDIUM',
      finding: n.data,
      verified: false,
      simulated: true,
    })),
    risk_score: chain.cvss || 7.8,
    severity: chain.severity || 'HIGH',
    cvss: chain.cvss || 7.8,
    confidence: 'MEDIUM',
    exploit_available: true,
    tags: chain.tags,
    target: scanResult.target,
    simulated_steps: chain.nodes.length,
  };
}

/**
 * Build an AD-based attack path.
 */
function buildADPath(chain, scanResult) {
  return {
    id: uuidv4(),
    chain_id: chain.id,
    name: chain.adPath?.name || 'Active Directory Attack Path',
    type: 'ACTIVE_DIRECTORY',
    steps: chain.nodes.map((n, i) => ({
      stage: n.stage,
      description: `[SIMULATED] ${n.data?.action || n.label}: ${n.data?.description || ''}`,
      tool: i === 0 ? 'BloodHound / Impacket' : 'CrackMapExec / Mimikatz (simulated)',
      confidence: 'MEDIUM',
      finding: n.data,
      verified: false,
      simulated: true,
    })),
    risk_score: chain.cvss || 9.0,
    severity: chain.severity || 'CRITICAL',
    cvss: chain.cvss || 9.0,
    confidence: 'MEDIUM',
    exploit_available: true,
    tags: chain.tags,
    target: scanResult.target,
    simulated_steps: chain.nodes.length,
  };
}

// ─── Utility Helpers ─────────────────────────────────────────

function buildPathName(chain, type) {
  const svc = chain.nodes.find(n => n.stage === 'SERVICE');
  const vuln = chain.nodes.find(n => n.stage === 'VULNERABILITY');
  const port = chain.nodes.find(n => n.stage === 'PORT');
  const svcLabel = svc?.label || `Port ${port?.data?.port}`;
  const vulnLabel = vuln?.data?.cve || '';
  if (type === 'full_compromise') return `${svcLabel} (${vulnLabel}) → Initial Access → PrivEsc → Full Compromise`;
  return `${svcLabel} ${vulnLabel ? `(${vulnLabel})` : ''} → Initial Access`;
}

function computeRiskScore(chain) {
  let score = chain.cvss || 5.0;
  if (chain.exploit_available) score = Math.min(10, score + 0.5);
  if (chain.initial_access) score = Math.min(10, score + 0.3);
  return Math.round(score * 10) / 10;
}

function computeConfidence(chain) {
  if (!chain.confirmed) return 'LOW';
  if (chain.exploit_available && chain.confirmed) return 'HIGH';
  return 'MEDIUM';
}

function rankScore(chain) {
  let score = chain.cvss || 0;
  if (chain.exploit_available) score += 1;
  if (chain.initial_access) score += 2;
  if (chain.type === 'FULL_COMPROMISE') score += 1.5;
  return score;
}

function deduplicateAndRank(paths) {
  // Sort by risk score desc
  const sorted = paths.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
  // Remove duplicates by chain_id
  const seen = new Set();
  return sorted.filter(p => {
    const key = p.chain_id + p.type;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

module.exports = { generateAttackPaths };
