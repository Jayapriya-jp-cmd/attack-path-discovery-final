// ─────────────────────────────────────────
//  MongoDB Connection Manager
// ─────────────────────────────────────────
const mongoose = require('mongoose');
const config = require('../config');

let connected = false;

/**
 * Initialize MongoDB connection.
 * Returns true on success, false on failure (system continues in-memory).
 */
async function init() {
  try {
    await mongoose.connect(config.mongodb.uri, {
      dbName: config.mongodb.dbName,
    });

    connected = true;
    console.log(`[MongoDB] Connected to ${config.mongodb.uri}/${config.mongodb.dbName}`);
    return true;
  } catch (err) {
    console.error('[MongoDB] Connection failed:', err.message);
    console.log('[MongoDB] Falling back to in-memory mode (no persistence)');
    connected = false;
    return false;
  }
}

/**
 * Check if MongoDB is connected.
 */
function isConnected() {
  return connected && mongoose.connection.readyState === 1;
}

/**
 * Close MongoDB connection gracefully.
 */
async function close() {
  if (mongoose.connection.readyState !== 0) {
    await mongoose.connection.close();
    connected = false;
    console.log('[MongoDB] Connection closed');
  }
}

module.exports = { init, isConnected, close };
