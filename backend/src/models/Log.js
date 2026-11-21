/**
 * Log Mongoose Schema
 * Stores prediction log events produced by ML service predictions.
 */

const mongoose = require('mongoose');

const logSchema = new mongoose.Schema(
  {
    timestamp: {
      type: Date,
      default: Date.now,
      index: true
    },
    datasetType: {
      type: String,
      required: true,
      enum: ['nsl_kdd', 'cicids2017'],
      index: true
    },
    prediction: {
      type: String,
      required: true,
      index: true
    },
    predictionIndex: {
      type: Number,
      required: true
    },
    confidence: {
      type: Number,
      required: true,
      min: 0.0,
      max: 1.0
    },
    modelVersion: {
      type: String,
      required: true
    },
    recordsProcessed: {
      type: Number,
      default: 1
    },
    classProbabilities: {
      type: Map,
      of: Number,
      default: {}
    },
    processingLatencyMs: {
      type: Number,
      default: 0
    },
    sourceInfo: {
      type: mongoose.Schema.Types.Mixed,
      default: null
    }
  },
  {
    timestamps: false,
    versionKey: false
  }
);

logSchema.index({ timestamp: -1, datasetType: 1 });
logSchema.index({ prediction: 1, datasetType: 1 });
logSchema.index({ timestamp: -1, prediction: 1 });

module.exports = mongoose.model('Log', logSchema);
