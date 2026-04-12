// ─────────────────────────────────────────
//  Centralized Configuration
// ─────────────────────────────────────────
require('dotenv').config();

module.exports = {
  port: parseInt(process.env.PORT, 10) || 4000,
  nodeEnv: process.env.NODE_ENV || 'development',

  neo4j: {
    uri: process.env.NEO4J_URI || 'bolt://localhost:7687',
    username: process.env.NEO4J_USERNAME || process.env.NEO4J_USER || 'neo4j',
    password: process.env.NEO4J_PASSWORD || 'password',
    database: process.env.NEO4J_DATABASE || 'neo4j',
  },

  mongodb: {
    uri: process.env.MONGODB_URI || 'mongodb://localhost:27017',
    dbName: process.env.MONGODB_DB || 'attack-path-discovery',
  },

  jwt: {
    secret: process.env.JWT_SECRET || 'apd-default-secret-change-in-production-2024',
    expiresIn: process.env.JWT_EXPIRES_IN || '24h',
  },

  nvdApiKey: process.env.NVD_API_KEY || '',
  scanTimeoutMs: parseInt(process.env.SCAN_TIMEOUT_MS, 10) || 120000,
};
