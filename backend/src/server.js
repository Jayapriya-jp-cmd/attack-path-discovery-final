// ─────────────────────────────────────────
//  Express Server + Socket.IO
// ─────────────────────────────────────────
const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server: SocketIO } = require('socket.io');
const config = require('./config');
const neo4jDb = require('./db/neo4j');
const mongoDb = require('./db/mongo');
const { applySchema } = require('./db/schema');
const { apiLimiter } = require('./middleware/rateLimiter');

// Route handlers
const authRoutes = require('./routes/auth');
const scanRoutes = require('./routes/scan');
const graphRoutes = require('./routes/graph');
const reportRoutes = require('./routes/report');
const historyRoutes = require('./routes/history');

const app = express();
const server = http.createServer(app);

// ── Socket.IO ──
const io = new SocketIO(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
});
app.set('io', io);

io.on('connection', (socket) => {
  console.log(`[Socket.IO] Client connected: ${socket.id}`);
  socket.on('disconnect', () => {
    console.log(`[Socket.IO] Client disconnected: ${socket.id}`);
  });
});

// ── Middleware ──
app.use(cors());
app.use(express.json());
app.use(apiLimiter);

// ── Health check ──
app.get('/api', (req, res) => {
  res.json({
    name: 'Attack Path Discovery API',
    version: '2.0.0',
    status: 'running',
    mode: 'real-execution-only',
    neo4jConnected: neo4jDb.isConnected(),
    mongoConnected: mongoDb.isConnected(),
  });
});

// ── Routes ──
app.use('/api/auth', authRoutes);
app.use('/api/scan', scanRoutes);
app.use('/api/graph', graphRoutes);
app.use('/api/report', reportRoutes);
app.use('/api/history', historyRoutes);

// ── Error handler ──
app.use((err, req, res, next) => {
  console.error('[Server] Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ── Start ──
async function start() {
  console.log('\n╔══════════════════════════════════════════════════════════╗');
  console.log('║        ATTACK PATH DISCOVERY SYSTEM v2.0.0              ║');
  console.log('║        REAL EXECUTION ONLY • NO MOCK DATA               ║');
  console.log('╚══════════════════════════════════════════════════════════╝\n');

  // Initialize MongoDB
  const mongoReady = await mongoDb.init();
  console.log(`[Config] MongoDB: ${mongoReady ? 'Connected' : 'Not connected (no persistence)'}`);

  // Initialize Neo4j
  const neo4jReady = await neo4jDb.init();
  if (neo4jReady) {
    await applySchema();
  }

  console.log(`[Config] Mode: REAL EXECUTION ONLY (no mock fallbacks)`);
  console.log(`[Config] Neo4j: ${neo4jDb.isConnected() ? 'Connected' : 'Not connected (in-memory mode)'}`);
  console.log(`[Config] JWT: Active (expires in ${config.jwt.expiresIn})`);

  server.listen(config.port, () => {
    console.log(`\n[Server] API running at http://localhost:${config.port}/api`);
    console.log(`[Server] Ready to accept scan requests\n`);
  });
}

// ── Graceful shutdown ──
async function shutdown() {
  console.log('\n[Server] Shutting down...');
  await neo4jDb.close();
  await mongoDb.close();
  server.close();
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

start().catch(err => {
  console.error('[Server] Failed to start:', err);
  process.exit(1);
});

module.exports = { app, server };
