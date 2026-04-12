// ============================================================
//  PHASE 8: NEO4J INTEGRATION — Neo4jService
//  Stores attack path graph nodes and relationships.
// ============================================================

const neo4j = require('neo4j-driver');

let driver = null;
let connected = false;

/**
 * Initialize Neo4j connection.
 */
function init() {
  const uri = process.env.NEO4J_URI || 'bolt://localhost:7687';
  const user = process.env.NEO4J_USER || 'neo4j';
  const password = process.env.NEO4J_PASSWORD || '';

  driver = neo4j.driver(uri, neo4j.auth.basic(user, password), {
    connectionAcquisitionTimeout: 5000,
    connectionTimeout: 5000,
  });
  return driver;
}

/**
 * Test Neo4j connection.
 */
async function testConnection() {
  if (!driver) init();
  const session = driver.session();
  try {
    await session.run('RETURN 1');
    connected = true;
    console.log('✅ Neo4j connected successfully');
    return true;
  } catch (e) {
    connected = false;
    console.warn('⚠️  Neo4j not available:', e.message);
    return false;
  } finally {
    await session.close();
  }
}

/**
 * Store a full scan's attack graph in Neo4j.
 * @param {string} scanId
 * @param {object} scanResult
 * @param {Array} vulnerabilities
 * @param {Array} exploits
 * @param {Array} attackPaths
 */
async function storeScanGraph(scanId, scanResult, vulnerabilities, exploits, attackPaths) {
  if (!connected) {
    console.warn('Neo4j not connected — skipping graph storage.');
    return false;
  }

  const session = driver.session({ database: process.env.NEO4J_DATABASE || 'neo4j' });

  try {
    // Clear previous scan data
    await session.run(
      'MATCH (n {scanId: $scanId}) DETACH DELETE n',
      { scanId }
    );

    // Create Target node
    await session.run(
      `CREATE (t:Target {
        scanId: $scanId,
        ip: $ip,
        hostname: $hostname,
        os: $os,
        timestamp: $timestamp
      })`,
      {
        scanId,
        ip: scanResult.target,
        hostname: scanResult.hostname || scanResult.target,
        os: scanResult.osInfo || 'Unknown',
        timestamp: scanResult.timestamp || new Date().toISOString(),
      }
    );

    // Create Port and Service nodes
    for (const svc of scanResult.services) {
      await session.run(
        `MATCH (t:Target {scanId: $scanId, ip: $ip})
         CREATE (p:Port {scanId: $scanId, port: $port, protocol: $protocol, state: 'open'})
         CREATE (s:Service {
           scanId: $scanId,
           name: $name,
           product: $product,
           version: $version,
           banner: $banner,
           port: $port
         })
         CREATE (t)-[:HAS_PORT]->(p)
         CREATE (p)-[:RUNS]->(s)`,
        {
          scanId,
          ip: scanResult.target,
          port: neo4j.int(svc.port),
          protocol: svc.protocol || 'tcp',
          name: svc.name || 'unknown',
          product: svc.product || '',
          version: svc.version || '',
          banner: svc.fullVersion || '',
        }
      );
    }

    // Create Vulnerability nodes
    for (const vuln of vulnerabilities) {
      await session.run(
        `MATCH (s:Service {scanId: $scanId, port: $port})
         CREATE (v:Vulnerability {
           scanId: $scanId,
           cve: $cve,
           description: $description,
           cvss: $cvss,
           severity: $severity,
           exploit_available: $exploit_available
         })
         CREATE (s)-[:HAS_VULNERABILITY]->(v)`,
        {
          scanId,
          port: neo4j.int(vuln.affectedPort),
          cve: vuln.id || vuln.cve,
          description: (vuln.description || '').slice(0, 500),
          cvss: vuln.cvss_v3 || 0,
          severity: vuln.severity || 'UNKNOWN',
          exploit_available: vuln.exploit_available || false,
        }
      );
    }

    // Create Exploit nodes
    for (const exploit of exploits) {
      await session.run(
        `MATCH (v:Vulnerability {scanId: $scanId})
         WHERE $cveRef IS NULL OR v.cve = $cveRef
         WITH v LIMIT 1
         CREATE (e:Exploit {
           scanId: $scanId,
           title: $title,
           path: $path,
           type: $type,
           platform: $platform
         })
         CREATE (v)-[:CAN_EXPLOIT]->(e)`,
        {
          scanId,
          cveRef: exploit.cve_reference || null,
          title: exploit.title || '',
          path: exploit.path || '',
          type: exploit.type || 'remote',
          platform: exploit.platform || 'unknown',
        }
      );
    }

    // Create AccessLevel nodes and attack path relationships
    for (const path of attackPaths.slice(0, 5)) {
      // Create path node
      await session.run(
        `CREATE (ap:AttackPath {
           scanId: $scanId,
           pathId: $pathId,
           name: $name,
           type: $pathType,
           risk_score: $risk_score,
           severity: $severity,
           confidence: $confidence
         })`,
        {
          scanId,
          pathId: path.id,
          name: (path.name || '').slice(0, 200),
          pathType: path.type || 'UNKNOWN',
          risk_score: path.risk_score || 0,
          severity: path.severity || 'UNKNOWN',
          confidence: path.confidence || 'LOW',
        }
      );

      // Link path to target
      await session.run(
        `MATCH (t:Target {scanId: $scanId}), (ap:AttackPath {scanId: $scanId, pathId: $pathId})
         CREATE (t)-[:HAS_ATTACK_PATH]->(ap)`,
        { scanId, pathId: path.id }
      );
    }

    console.log(`✅ Scan ${scanId} stored in Neo4j`);
    return true;
  } catch (e) {
    console.error('Neo4j store error:', e.message);
    return false;
  } finally {
    await session.close();
  }
}

/**
 * Retrieve graph data for a scan (nodes + edges for Cytoscape.js).
 * @param {string} scanId
 * @returns {object} { nodes, edges }
 */
async function getGraphData(scanId) {
  if (!connected) {
    return { nodes: [], edges: [], error: 'Neo4j not connected' };
  }

  const session = driver.session({ database: process.env.NEO4J_DATABASE || 'neo4j' });

  try {
    // Get all nodes for scan
    const nodesResult = await session.run(
      `MATCH (n {scanId: $scanId}) RETURN n, labels(n) as labels, id(n) as nodeId`,
      { scanId }
    );

    // Get all relationships
    const edgesResult = await session.run(
      `MATCH (a {scanId: $scanId})-[r]->(b {scanId: $scanId})
       RETURN id(a) as fromId, id(b) as toId, type(r) as relType, id(r) as edgeId`,
      { scanId }
    );

    const nodes = nodesResult.records.map(r => {
      const node = r.get('n').properties;
      const labels = r.get('labels');
      const nodeId = r.get('nodeId').toString();
      return {
        data: {
          id: nodeId,
          label: getNodeLabel(node, labels),
          type: labels[0] || 'Unknown',
          ...node,
        },
      };
    });

    const edges = edgesResult.records.map(r => ({
      data: {
        id: r.get('edgeId').toString(),
        source: r.get('fromId').toString(),
        target: r.get('toId').toString(),
        label: r.get('relType'),
      },
    }));

    return { nodes, edges };
  } catch (e) {
    console.error('Neo4j graph fetch error:', e.message);
    return { nodes: [], edges: [], error: e.message };
  } finally {
    await session.close();
  }
}

/**
 * Get all scan IDs.
 */
async function getAllScans() {
  if (!connected) return [];
  const session = driver.session({ database: process.env.NEO4J_DATABASE || 'neo4j' });
  try {
    const result = await session.run(
      'MATCH (t:Target) RETURN t.scanId as scanId, t.ip as ip, t.timestamp as ts ORDER BY ts DESC LIMIT 20'
    );
    return result.records.map(r => ({
      scanId: r.get('scanId'),
      ip: r.get('ip'),
      timestamp: r.get('ts'),
    }));
  } catch {
    return [];
  } finally {
    await session.close();
  }
}

function getNodeLabel(props, labels) {
  if (labels.includes('Target')) return props.ip || 'Target';
  if (labels.includes('Port')) return `Port ${props.port}`;
  if (labels.includes('Service')) return `${props.product || props.name} ${props.version || ''}`.trim();
  if (labels.includes('Vulnerability')) return props.cve || 'Vulnerability';
  if (labels.includes('Exploit')) return props.title?.slice(0, 40) || 'Exploit';
  if (labels.includes('AttackPath')) return props.name?.slice(0, 40) || 'Attack Path';
  return labels[0] || 'Node';
}

async function close() {
  if (driver) await driver.close();
}

module.exports = { init, testConnection, storeScanGraph, getGraphData, getAllScans, close, isConnected: () => connected };
