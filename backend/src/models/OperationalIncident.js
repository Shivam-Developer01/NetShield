const mongoose = require('mongoose');

const operationalIncidentSchema = new mongoose.Schema({
  type: {
    type: String,
    required: true,
    index: true
  },
  severity: {
    type: String,
    enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    default: 'MEDIUM',
    required: true,
    index: true
  },
  status: {
    type: String,
    enum: ['OPEN', 'ACKNOWLEDGED', 'RESOLVED'],
    default: 'OPEN',
    required: true,
    index: true
  },
  source: {
    type: String,
    required: true,
    default: 'system'
  },
  message: {
    type: String,
    required: true
  },
  metric: {
    type: String,
    default: null
  },
  currentValue: {
    type: mongoose.Schema.Types.Mixed,
    default: null
  },
  threshold: {
    type: mongoose.Schema.Types.Mixed,
    default: null
  },
  firstDetectedAt: {
    type: Date,
    default: Date.now,
    index: true
  },
  lastDetectedAt: {
    type: Date,
    default: Date.now
  },
  resolvedAt: {
    type: Date,
    default: null
  },
  occurrenceCount: {
    type: Number,
    default: 1
  },
  requestId: {
    type: String,
    default: null
  },
  metadata: {
    type: Map,
    of: String,
    default: {}
  }
}, {
  timestamps: true
});

operationalIncidentSchema.index({ status: 1, severity: 1, createdAt: -1 });

module.exports = mongoose.model('OperationalIncident', operationalIncidentSchema);
