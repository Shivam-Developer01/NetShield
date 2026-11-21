/**
 * System Metric Controller
 * Serves dashboard telemetry and aggregated threat statistics.
 * Telemetry Categories:
 * - measured: totalFlows, benignFlows, maliciousFlows, activeAlerts, avgLatencyMs
 * - calculated: detectionRate ((maliciousFlows / totalFlows) * 100)
 */

const mongoose = require('mongoose');
const Log = require('../models/Log');
const Alert = require('../models/Alert');
const SystemMetric = require('../models/SystemMetric');
const mlService = require('../services/mlService');

const getSystemMetrics = async (req, res, next) => {
  try {
    const validDatasets = ['nsl_kdd', 'cicids2017', 'all'];
    const rawDataset = req.query.datasetType ? String(req.query.datasetType).trim().toLowerCase() : undefined;

    if (rawDataset && !validDatasets.includes(rawDataset)) {
      return res.status(400).json({
        success: false,
        error: `Invalid datasetType '${req.query.datasetType}'. Allowed values: 'nsl_kdd', 'cicids2017', or 'all'.`
      });
    }

    const requestedDataset = rawDataset && rawDataset !== 'all' ? rawDataset : null;
    const logFilter = requestedDataset ? { datasetType: requestedDataset } : {};
    const alertFilter = requestedDataset ? { datasetType: requestedDataset } : {};

    const [totalFlows, benignFlows, activeAlerts, latestStoredMetric, mlHealth] = await Promise.all([
      Log.countDocuments(logFilter),
      Log.countDocuments({ ...logFilter, prediction: { $in: ['Normal', 'BENIGN'] } }),
      Alert.countDocuments({ ...alertFilter, status: { $in: ['open', 'acknowledged'] } }),
      SystemMetric.findOne(requestedDataset ? { datasetType: requestedDataset } : {}).sort({ timestamp: -1 }).lean(),
      mlService.checkHealth(req.requestId)
    ]);

    const maliciousFlows = totalFlows - benignFlows;
    const detectionRate = totalFlows > 0 ? parseFloat(((maliciousFlows / totalFlows) * 100).toFixed(2)) : 0.0;

    // Calculate average latency from recent 100 logs matching the dataset scope
    const recentLogs = await Log.find(logFilter, { processingLatencyMs: 1 }).sort({ timestamp: -1 }).limit(100).lean();
    const avgLatencyMs = recentLogs.length > 0
      ? parseFloat((recentLogs.reduce((acc, curr) => acc + (curr.processingLatencyMs || 0), 0) / recentLogs.length).toFixed(2))
      : 0.0;

    const dbState = mongoose.connection.readyState;
    const dbStatus = dbState === 1 ? 'connected' : (dbState === 2 ? 'connecting' : 'disconnected');

    const metrics = {
      timestamp: new Date().toISOString(),
      requestId: req.requestId || null,
      datasetType: requestedDataset || 'all',
      measured: {
        totalFlows,
        benignFlows,
        maliciousFlows,
        activeAlerts,
        processingLatencyMs: avgLatencyMs
      },
      calculated: {
        detectionRate
      },
      system: {
        database: dbStatus,
        ml_service: mlHealth.status || 'unknown'
      },
      lastUpdated: latestStoredMetric ? latestStoredMetric.timestamp : new Date().toISOString()
    };

    res.status(200).json({
      success: true,
      data: metrics
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  getSystemMetrics
};
