/**
 * Alert Mongoose Schema
 * Stores security threat alerts automatically generated from malicious predictions.
 */

const mongoose = require('mongoose');

const alertSchema = new mongoose.Schema(
  {
    timestamp: {
      type: Date,
      default: Date.now,
      index: true
    },
    severity: {
      type: String,
      required: true,
      enum: ['low', 'medium', 'high', 'critical'],
      index: true
    },
    attackType: {
      type: String,
      required: true,
      index: true
    },
    prediction: {
      type: String,
      required: true
    },
    confidence: {
      type: Number,
      required: true,
      min: 0.0,
      max: 1.0
    },
    datasetType: {
      type: String,
      required: true,
      enum: ['nsl_kdd', 'cicids2017'],
      index: true
    },
    modelVersion: {
      type: String,
      required: true
    },
    status: {
      type: String,
      enum: ['open', 'acknowledged', 'resolved'],
      default: 'open',
      index: true
    },
    description: {
      type: String,
      required: true
    },
    sourceInfo: {
      type: mongoose.Schema.Types.Mixed,
      default: null
    },
    acknowledgedAt: {
      type: Date,
      default: null
    },
    resolvedAt: {
      type: Date,
      default: null
    }
  },
  {
    timestamps: false,
    versionKey: false
  }
);

alertSchema.index({ timestamp: -1, severity: 1 });
alertSchema.index({ status: 1, datasetType: 1 });
alertSchema.index({ timestamp: -1, datasetType: 1, status: 1 });

module.exports = mongoose.model('Alert', alertSchema);
