// ═══════════════════════════════════════════════════════════
//  Correlation Engine — Builds graph from REAL scan data ONLY
//  Creates nodes and edges ONLY from parsed tool outputs.
//  NO synthetic nodes. NO assumed relationships.
// ═══════════════════════════════════════════════════════════

/**
 * Build a correlation graph from REAL scan results.
 * Every node and edge must trace back to actual tool output.
 *
 * @param {Object} data - { recon, vulns, exploits, privEsc, ad }
 * @returns {{ nodes: Array, edges: Array }}
 */
function correlate(data) {
  console.log(`\n[Correlation] ══════════════════════════════════════`);
  console.log(`[Correlation] BUILDING GRAPH FROM REAL DATA`);
  console.log(`[Correlation] ══════════════════════════════════════`);

  const nodes = [];
  const edges = [];
  const nodeIds = new Set();

  const recon = data.recon || {};
  const vulns = data.vulns || [];
  const exploits = data.exploits || [];
  const privEsc = data.privEsc || [];

  // Helper: add node only if not already added
  function addNode(id, type, label, nodeData = {}) {
    if (nodeIds.has(id)) return;
    nodeIds.add(id);
    nodes.push({ id, type, label, data: nodeData });
  }

  function addEdge(source, target, type) {
    edges.push({ source, target, type });
  }

  // ── Target node (from REAL recon) ──
  if (recon.target) {
    addNode('target', 'target', recon.target, {
      ip: recon.target,
      os: recon.os?.name || 'Unknown',
      osFamily: recon.os?.family || 'Unknown',
      scanTime: recon.scanTime,
      scanType: recon.scanType || 'REAL',
    });
    console.log(`[Correlation] + Target: ${recon.target} (OS: ${recon.os?.name || 'Unknown'})`);
  }

  // ── Ports (from REAL Nmap output) ──
  if (recon.ports && recon.ports.length > 0) {
    for (const port of recon.ports) {
      const portId = `port_${port.number}`;
      addNode(portId, 'port', `${port.number}/${port.protocol}`, {
        number: port.number,
        protocol: port.protocol,
        state: port.state,
        source: 'nmap_real',
      });
      addEdge('target', portId, 'HAS_PORT');

      // Service node (from REAL Nmap service detection)
      const svc = port.service;
      if (svc && svc.name !== 'unknown') {
        const svcId = `svc_${port.number}_${svc.name}`;
        addNode(svcId, 'service', `${svc.product || svc.name} ${svc.version || ''}`.trim(), {
          name: svc.name,
          product: svc.product,
          version: svc.version,
          extraInfo: svc.extraInfo,
          source: 'nmap_real',
        });
        addEdge(portId, svcId, 'RUNS_SERVICE');
        console.log(`[Correlation] + Port ${port.number} → ${svc.product || svc.name} ${svc.version || ''}`);
      }
    }
  } else {
    console.log(`[Correlation] No open ports found — graph will be minimal`);
  }

  // ── Vulnerabilities (from CVE matching against real services) ──
  for (const vuln of vulns) {
    const vulnId = `vuln_${vuln.cve || 'unknown'}_${vuln.port}`;
    addNode(vulnId, 'vulnerability', vuln.cve || 'Unnamed Vuln', {
      cve: vuln.cve,
      description: vuln.description,
      severity: vuln.severity,
      cvss: vuln.cvss,
      port: vuln.port,
      matchBasis: vuln.matchBasis || '',
      source: vuln.source || 'cve-lookup',
    });

    // Link to the service that was detected
    const svcNode = nodes.find(n => n.type === 'service' && n.data.name === vuln.service);
    if (svcNode) {
      addEdge(svcNode.id, vulnId, 'HAS_VULNERABILITY');
    } else {
      addEdge(`port_${vuln.port}`, vulnId, 'HAS_VULNERABILITY');
    }
    console.log(`[Correlation] + Vuln: ${vuln.cve} (${vuln.severity}) on port ${vuln.port}`);
  }

  // ── Exploits (from REAL Searchsploit output) ──
  for (const exp of exploits) {
    const expId = `exploit_${exp.edb_id || exploits.indexOf(exp)}`;
    addNode(expId, 'exploit', exp.title || 'Unknown Exploit', {
      edb_id: exp.edb_id,
      title: exp.title,
      path: exp.path,
      type: exp.type,
      platform: exp.platform,
      verified: exp.verified,
      date: exp.date,
      searchQuery: exp.searchQuery,
      source: exp.source || 'searchsploit_real',
    });

    // Link to matching vulnerability or service
    const matchVuln = vulns.find(v => v.port === exp.port);
    if (matchVuln) {
      const vulnId = `vuln_${matchVuln.cve || 'unknown'}_${matchVuln.port}`;
      if (nodeIds.has(vulnId)) {
        addEdge(vulnId, expId, 'HAS_EXPLOIT');
      }
    }

    // Also link to the service directly
    const svcNode = nodes.find(n => n.type === 'service' && n.data.name === exp.service);
    if (svcNode) {
      addEdge(svcNode.id, expId, 'CAN_BE_EXPLOITED_BY');
    }
    console.log(`[Correlation] + Exploit: EDB-${exp.edb_id || '?'} "${exp.title?.substring(0, 60)}"`);
  }

  // ── PrivEsc Vectors (inferred from real data) ──
  for (const vec of privEsc) {
    const vecId = `privesc_${privEsc.indexOf(vec)}`;
    addNode(vecId, 'privesc', vec.name, {
      type: vec.type,
      description: vec.description,
      severity: vec.severity,
      confidence: vec.confidence,
      mitigation: vec.mitigation,
      basis: vec.basis,
    });

    // Link to relevant service
    const relatedSvc = nodes.find(n =>
      n.type === 'service' &&
      vec.basis && vec.basis.toLowerCase().includes(n.data.name?.toLowerCase())
    );
    if (relatedSvc) {
      addEdge(relatedSvc.id, vecId, 'POTENTIAL_PRIVESC');
    } else {
      addEdge('target', vecId, 'POTENTIAL_PRIVESC');
    }
    console.log(`[Correlation] + PrivEsc: ${vec.name} [${vec.confidence}]`);
  }

  console.log(`[Correlation] ✓ Graph: ${nodes.length} nodes, ${edges.length} edges (all from real data)`);
  return { nodes, edges };
}

module.exports = { correlate };
