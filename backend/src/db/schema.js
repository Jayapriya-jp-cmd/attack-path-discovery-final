// ─────────────────────────────────────────
//  Neo4j Schema — Indexes & Constraints
// ─────────────────────────────────────────
const db = require('./neo4j');

const SCHEMA_QUERIES = [
  // Constraints (unique properties)
  'CREATE CONSTRAINT target_ip IF NOT EXISTS FOR (t:Target) REQUIRE t.ip IS UNIQUE',
  'CREATE CONSTRAINT vuln_cve IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cve IS UNIQUE',

  // Indexes for fast lookup
  'CREATE INDEX port_number IF NOT EXISTS FOR (p:Port) ON (p.number)',
  'CREATE INDEX service_name IF NOT EXISTS FOR (s:Service) ON (s.name)',
  'CREATE INDEX exploit_title IF NOT EXISTS FOR (e:Exploit) ON (e.title)',
  'CREATE INDEX access_level IF NOT EXISTS FOR (a:AccessLevel) ON (a.level)',
];

/**
 * Apply schema constraints and indexes.
 * Safe to run multiple times (IF NOT EXISTS).
 */
async function applySchema() {
  if (!db.isConnected()) {
    console.log('[Schema] Skipped — no database connection');
    return;
  }

  console.log('[Schema] Applying indexes and constraints...');
  for (const query of SCHEMA_QUERIES) {
    try {
      await db.writeQuery(query);
    } catch (err) {
      // Some Aura free tiers don't support all constraint types
      console.warn(`[Schema] Warning: ${err.message}`);
    }
  }
  console.log('[Schema] Done');
}

module.exports = { applySchema };
