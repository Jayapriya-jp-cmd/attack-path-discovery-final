// ═══════════════════════════════════════════════════════════
//  Path Generator — Data-driven attack path generation
//  Generates paths ONLY from real detected data.
//  Rule: IF service exists AND exploit exists → create path.
//  No assumptions. No fabricated chains.
// ═══════════════════════════════════════════════════════════
const neo4jDb = require('../db/neo4j');

/**
 * Generate ranked attack paths from REAL correlation graph data.
 * Each path step MUST trace back to an actual finding.
 *
 * @param {{ nodes, edges }} graph - Correlation graph from real data
 * @param {string} scanId - Unique scan identifier
 * @returns {Array} Ranked attack paths
 */
async function generatePaths(graph, scanId) {
  console.log(`\n[PathGen] ══════════════════════════════════════`);
  console.log(`[PathGen] GENERATING ATTACK PATHS FROM REAL DATA`);
  console.log(`[PathGen] Input: ${graph.nodes.length} nodes, ${graph.edges.length} edges`);
  console.log(`[PathGen] ══════════════════════════════════════`);

  const paths = [];
  const nodeMap = {};
  graph.nodes.forEach(n => { nodeMap[n.id] = n; });

  // Find all service nodes
  const services = graph.nodes.filter(n => n.type === 'service');
  const exploits = graph.nodes.filter(n => n.type === 'exploit');
  const vulns = graph.nodes.filter(n => n.type === 'vulnerability');
  const privEscVecs = graph.nodes.filter(n => n.type === 'privesc');
  const targetNode = graph.nodes.find(n => n.type === 'target');

  console.log(`[PathGen] Services: ${services.length}, Exploits: ${exploits.length}, Vulns: ${vulns.length}, PrivEsc: ${privEscVecs.length}`);

  // ── Path Type 1: Service → Vulnerability → Exploit chains ──
  for (const exploit of exploits) {
    // Find the edge linking this exploit to a vulnerability or service
    const exploitEdges = graph.edges.filter(e => e.target === exploit.id);

    for (const edge of exploitEdges) {
      const parentNode = nodeMap[edge.source];
      if (!parentNode) continue;

      const chain = [];
      let riskScore = 0;

      // Trace back to target
      if (parentNode.type === 'vulnerability') {
        // Full chain: Target → Port → Service → Vulnerability → Exploit
        const vulnEdges = graph.edges.filter(e => e.target === parentNode.id);
        for (const ve of vulnEdges) {
          const svcNode = nodeMap[ve.source];
          if (!svcNode) continue;

          const portEdges = graph.edges.filter(e => e.target === svcNode.id);
          const portNode = portEdges.length > 0 ? nodeMap[portEdges[0].source] : null;

          chain.push({
            step: 1,
            action: `Port ${portNode?.data?.number || '?'} is open`,
            finding: `Open port detected by Nmap`,
            confidence: 'Confirmed',
          });
          chain.push({
            step: 2,
            action: `${svcNode.label} running on port ${portNode?.data?.number || '?'}`,
            finding: `Service identified: ${svcNode.data?.product || svcNode.data?.name} ${svcNode.data?.version || ''}`,
            confidence: 'Confirmed',
          });
          chain.push({
            step: 3,
            action: `Vulnerability ${parentNode.label} affects this service`,
            finding: `${parentNode.data?.description || 'Known vulnerability'}`,
            severity: parentNode.data?.severity || 'Unknown',
            confidence: parentNode.data?.source === 'local-cve-db' ? 'Matched' : 'Confirmed',
          });
          chain.push({
            step: 4,
            action: `Exploit available: ${exploit.data?.title || 'Unknown'}`,
            finding: `EDB-${exploit.data?.edb_id || '?'} — ${exploit.data?.path || 'N/A'}`,
            confidence: exploit.data?.source === 'searchsploit_real' ? 'Real' : 'Database',
          });
          chain.push({
            step: 5,
            action: 'Possible initial access via exploit',
            finding: `If exploit is applicable and target is unpatched → initial foothold`,
            confidence: 'Theoretical',
          });

          riskScore = calculateRisk(parentNode, exploit);
        }
      } else if (parentNode.type === 'service') {
        // Direct: Target → Port → Service → Exploit
        const portEdges = graph.edges.filter(e => e.target === parentNode.id);
        const portNode = portEdges.length > 0 ? nodeMap[portEdges[0].source] : null;

        chain.push({
          step: 1,
          action: `Port ${portNode?.data?.number || '?'} is open`,
          finding: 'Open port detected by Nmap',
          confidence: 'Confirmed',
        });
        chain.push({
          step: 2,
          action: `${parentNode.label} running`,
          finding: `Service: ${parentNode.data?.product || parentNode.data?.name} ${parentNode.data?.version || ''}`,
          confidence: 'Confirmed',
        });
        chain.push({
          step: 3,
          action: `Exploit available: ${exploit.data?.title || 'Unknown'}`,
          finding: `EDB-${exploit.data?.edb_id || '?'} — ${exploit.data?.type || 'N/A'}`,
          confidence: exploit.data?.source === 'searchsploit_real' ? 'Real' : 'Database',
        });

        riskScore = calculateRiskDirect(exploit);
      }

      if (chain.length > 0) {
        paths.push({
          id: `path_${paths.length + 1}`,
          name: `${parentNode.label} → ${exploit.data?.title?.substring(0, 40) || 'Exploit'}`,
          steps: chain,
          riskScore,
          dataSource: 'All steps derived from real tool output',
        });
        console.log(`[PathGen] + Path: ${chain.length} steps, risk ${riskScore}`);
      }
    }
  }

  // ── Path Type 2: Service → PrivEsc (no exploit needed) ──
  for (const pv of privEscVecs) {
    const pvEdges = graph.edges.filter(e => e.target === pv.id);
    for (const edge of pvEdges) {
      const parentNode = nodeMap[edge.source];
      if (!parentNode) continue;

      const chain = [];

      if (parentNode.type === 'service') {
        const portEdges = graph.edges.filter(e => e.target === parentNode.id);
        const portNode = portEdges.length > 0 ? nodeMap[portEdges[0].source] : null;

        chain.push({
          step: 1,
          action: `Service ${parentNode.label} accessible on port ${portNode?.data?.number || '?'}`,
          finding: 'Service detected by Nmap',
          confidence: 'Confirmed',
        });
        chain.push({
          step: 2,
          action: `Potential: ${pv.label}`,
          finding: pv.data?.description || 'Privilege escalation vector',
          confidence: pv.data?.confidence || 'Inferred',
        });
        chain.push({
          step: 3,
          action: 'If misconfigured → privilege escalation',
          finding: `Mitigation: ${pv.data?.mitigation || 'Review service configuration'}`,
          confidence: 'Theoretical',
        });
      }

      if (chain.length > 0) {
        const risk = pv.data?.severity === 'Critical' ? 8 : pv.data?.severity === 'High' ? 6 : 4;
        paths.push({
          id: `path_${paths.length + 1}`,
          name: `${parentNode.label} → ${pv.label}`,
          steps: chain,
          riskScore: risk,
          dataSource: `Inferred from real Nmap data (${pv.data?.basis || 'service detection'})`,
        });
        console.log(`[PathGen] + PrivEsc Path: ${chain.length} steps, risk ${risk}`);
      }
    }
  }

  // Sort by risk (highest first)
  paths.sort((a, b) => b.riskScore - a.riskScore);

  // Store in Neo4j if connected
  await storeInNeo4j(graph, paths, scanId);

  if (paths.length === 0) {
    console.log(`[PathGen] No attack paths generated — no exploitable service+exploit combinations found`);
    console.log(`[PathGen] This is correct if no real exploits were matched`);
  } else {
    console.log(`[PathGen] ✓ Generated ${paths.length} attack paths (all data-driven)`);
  }

  return paths;
}

/**
 * Calculate risk score from vulnerability and exploit data.
 */
function calculateRisk(vulnNode, exploitNode) {
  let score = 3; // Base score for having a path

  // CVSS from real CVE data
  if (vulnNode.data?.cvss) {
    score += vulnNode.data.cvss;
  }

  // Severity multiplier
  switch (vulnNode.data?.severity?.toLowerCase()) {
    case 'critical': score += 4; break;
    case 'high': score += 3; break;
    case 'medium': score += 2; break;
    case 'low': score += 1; break;
  }

  // Verified exploit bonus
  if (exploitNode.data?.verified) score += 1;

  return Math.min(10, Math.round(score * 10) / 10);
}

function calculateRiskDirect(exploitNode) {
  let score = 4; // Base for service→exploit without CVE
  if (exploitNode.data?.verified) score += 2;
  return Math.min(10, score);
}

/**
 * Store results in Neo4j — ONLY real data gets persisted.
 */
async function storeInNeo4j(graph, paths, scanId) {
  if (!neo4jDb.isConnected()) {
    console.log(`[PathGen] Neo4j not connected — skipping graph storage`);
    return;
  }

  console.log(`[PathGen] Storing graph in Neo4j...`);

  try {
    // Store nodes
    for (const node of graph.nodes) {
      await neo4jDb.runQuery(
        `MERGE (n:ScanNode {nodeId: $nodeId})
         SET n.type = $type, n.label = $label, n.scanId = $scanId,
             n.dataSource = $dataSource, n.timestamp = datetime()`,
        {
          nodeId: `${scanId}_${node.id}`,
          type: node.type,
          label: node.label,
          scanId,
          dataSource: node.data?.source || 'real_scan',
        }
      );
    }

    // Store edges
    for (const edge of graph.edges) {
      await neo4jDb.runQuery(
        `MATCH (a:ScanNode {nodeId: $source}), (b:ScanNode {nodeId: $target})
         MERGE (a)-[r:CONNECTS {type: $type}]->(b)
         SET r.scanId = $scanId`,
        {
          source: `${scanId}_${edge.source}`,
          target: `${scanId}_${edge.target}`,
          type: edge.type,
          scanId,
        }
      );
    }

    console.log(`[PathGen] ✓ Stored ${graph.nodes.length} nodes, ${graph.edges.length} edges in Neo4j`);
  } catch (err) {
    console.error(`[PathGen] Neo4j storage error: ${err.message}`);
  }
}

module.exports = { generatePaths };
