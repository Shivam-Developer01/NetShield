/**
 * SystemMetric Mongoose Schema
 * Stores periodic or aggregated system performance and threat statistics.
 * Telemetry Categories:
 * - measured: totalFlows, benignFlows, maliciousFlows, activeAlerts, processingLatencyMs
 * - calculated: detectionRate (percentage maliciousFlows / totalFlows)
 */

const mongoose = require('mongoose');

const systemMetricSchema = new mongoose.Schema(
  {
    timestamp: {
      type: Date,
      default: Date.now,
      index: true
    },
    totalFlows: {
      type: Number,
      default: 0
    },
    benignFlows: {
      type: Number,
      default: 0
    },
    maliciousFlows: {
      type: Number,
      default: 0
    },
    detectionRate: {
      type: Number,
      default: 0.0
    },
    processingLatencyMs: {
      type: Number,
      default: 0.0
    },
    activeAlerts: {
      type: Number,
      default: 0
    }
  },
  {
    timestamps: false,
    versionKey: false
  }
);

module.exports = mongoose.model('SystemMetric', systemMetricSchema);
