// ─────────────────────────────────────────
//  Scan Model — MongoDB + Mongoose
// ─────────────────────────────────────────
const mongoose = require('mongoose');

const scanSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  },
  scanId: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  target: {
    type: String,
    required: true,
  },
  scanResult: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
  attackPaths: {
    type: [mongoose.Schema.Types.Mixed],
    default: [],
  },
  graphData: {
    type: mongoose.Schema.Types.Mixed,
    default: { nodes: [], edges: [] },
  },
  summary: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
  duration: String,
  os: mongoose.Schema.Types.Mixed,
  ports: [mongoose.Schema.Types.Mixed],
  services: [mongoose.Schema.Types.Mixed],
  vulnerabilities: [mongoose.Schema.Types.Mixed],
  exploits: [mongoose.Schema.Types.Mixed],
  privEscVectors: [mongoose.Schema.Types.Mixed],
  adAnalysis: mongoose.Schema.Types.Mixed,
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Compound index for efficient history queries
scanSchema.index({ userId: 1, createdAt: -1 });

module.exports = mongoose.model('Scan', scanSchema);
