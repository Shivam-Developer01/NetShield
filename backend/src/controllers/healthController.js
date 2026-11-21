/**
 * NetShield Operational Health, Liveness & Readiness Controller
 */

const mongoose = require('mongoose');
const mlService = require('../services/mlService');
const metricsCollector = require('../utils/metricsCollector');
const operationalAlertEngine = require('../services/operationalAlertEngine');

// GET /live — Liveness probe (checks event loop responsiveness)
const getLiveness = (req, res) => {
  res.status(200).json({
    status: 'alive',
    timestamp: new Date().toISOString(),
    service: 'netshield-backend'
  });
};

// GET /ready — Readiness probe (checks critical dependencies before serving traffic)
const getReadiness = async (req, res) => {
  try {
    const dbState = mongoose.connection.readyState;
    const isDbConnected = dbState === 1;

    // ML service check
    const mlHealth = await mlService.checkHealth(req.requestId);
    const isMlHealthy = mlHealth && mlHealth.status === 'healthy';

    const isReady = isDbConnected && isMlHealthy;

    if (isReady) {
      return res.status(200).json({
        status: 'ready',
        timestamp: new Date().toISOString(),
        requestId: req.requestId || null,
        checks: {
          database: 'connected',
          mlService: 'healthy'
        }
      });
    } else {
      return res.status(503).json({
        status: 'not_ready',
        timestamp: new Date().toISOString(),
        requestId: req.requestId || null,
        checks: {
          database: isDbConnected ? 'connected' : 'disconnected',
          mlService: isMlHealthy ? 'healthy' : 'unavailable'
        }
      });
    }
  } catch (err) {
    return res.status(503).json({
      status: 'not_ready',
      timestamp: new Date().toISOString(),
      error: err.message
    });
  }
};

// GET /health — Comprehensive operational health breakdown
const getHealthStatus = async (req, res, next) => {
  try {
    const dbState = mongoose.connection.readyState;
    const dbStatus = dbState === 1 ? 'connected' : (dbState === 2 ? 'connecting' : 'disconnected');
    metricsCollector.dbStats.connectionState = dbStatus;

    // Quick ML service check with requestId
    const mlHealth = await mlService.checkHealth(req.requestId);
    const mlStatus = mlHealth && mlHealth.status ? mlHealth.status : 'unavailable';

    // Sensor status from metrics collector
    const sensorLastSeen = metricsCollector.sensorStats.lastSeenAt;
    const isSensorActive = sensorLastSeen && (Date.now() - new Date(sensorLastSeen).getTime() < 60000);
    const sensorStatus = isSensorActive ? 'healthy' : (sensorLastSeen ? 'degraded' : 'unknown');

    const socketStatus = 'healthy';
    const isFullyHealthy = dbState === 1 && mlStatus === 'healthy';
    const overallStatus = isFullyHealthy ? 'healthy' : 'degraded';

    // Trigger alert evaluation asynchronously
    operationalAlertEngine.evaluateMetrics().catch(() => {});

    res.status(200).json({
      status: overallStatus,
      timestamp: new Date().toISOString(),
      requestId: req.requestId || null,
      service: 'NetShield Node.js Backend',
      services: {
        backend: { status: 'healthy', uptimeSeconds: Math.floor(process.uptime()) },
        mongodb: { status: dbStatus === 'connected' ? 'healthy' : 'unhealthy', state: dbStatus },
        mlService: { status: mlStatus },
        socket: { status: socketStatus, activeConnections: metricsCollector.socketStats.activeConnections },
        sensor: { status: sensorStatus, lastSeenAt: sensorLastSeen }
      }
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  getLiveness,
  getReadiness,
  getHealthStatus
};
