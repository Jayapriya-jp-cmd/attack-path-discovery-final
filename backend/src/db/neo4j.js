// ─────────────────────────────────────────
//  Neo4j Driver — Singleton with mock fallback
// ─────────────────────────────────────────
const neo4j = require('neo4j-driver');
const config = require('../config');

let driver = null;
let connected = false;

/**
 * Initialize the Neo4j driver.
 * Returns true if connection succeeds, false otherwise.
 */
async function init() {
  // Connect to Neo4j

  try {
    driver = neo4j.driver(
      config.neo4j.uri,
      neo4j.auth.basic(config.neo4j.username, config.neo4j.password),
      {
        maxConnectionPoolSize: 50,
        connectionAcquisitionTimeout: 10000,
      }
    );

    // Verify connectivity
    const serverInfo = await driver.getServerInfo();
    console.log(`[Neo4j] Connected to ${serverInfo.address} (${serverInfo.protocolVersion})`);
    connected = true;
    return true;
  } catch (err) {
    console.error('[Neo4j] Connection failed:', err.message);
    console.log('[Neo4j] Falling back to in-memory mode');
    connected = false;
    return false;
  }
}

/**
 * Run a Cypher query. Returns records array.
 * Falls back to empty results if not connected.
 */
async function runQuery(cypher, params = {}) {
  if (!connected || !driver) {
    return [];
  }

  const session = driver.session({ database: config.neo4j.database });
  try {
    const result = await session.run(cypher, params);
    return result.records;
  } finally {
    await session.close();
  }
}

/**
 * Run a write transaction (for CREATE/MERGE operations).
 */
async function writeQuery(cypher, params = {}) {
  if (!connected || !driver) {
    return { nodesCreated: 0, relationshipsCreated: 0 };
  }

  const session = driver.session({ database: config.neo4j.database });
  try {
    const result = await session.executeWrite(tx => tx.run(cypher, params));
    const counters = result.summary.counters.updates();
    return counters;
  } finally {
    await session.close();
  }
}

/**
 * Clear all graph data (for resetting between scans).
 */
async function clearGraph() {
  return writeQuery('MATCH (n) DETACH DELETE n');
}

/**
 * Check if we have an active connection.
 */
function isConnected() {
  return connected;
}

/**
 * Close the driver gracefully.
 */
async function close() {
  if (driver) {
    await driver.close();
    connected = false;
    console.log('[Neo4j] Connection closed');
  }
}

module.exports = { init, runQuery, writeQuery, clearGraph, isConnected, close };
