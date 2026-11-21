const OperationalIncident = require('../models/OperationalIncident');
const metricsCollector = require('../utils/metricsCollector');
const eventPublisher = require('../realtime/eventPublisher');
const logger = require('../utils/logger');

class OperationalAlertEngine {
  constructor() {
    this.thresholds = {
      httpErrorRatePercent: parseFloat(process.env.OBS_HTTP_ERROR_RATE_THRESHOLD) || 5.0,
      mlLatencyMs: parseFloat(process.env.OBS_ML_LATENCY_THRESHOLD_MS) || 1000.0,
      authFailureCount: parseInt(process.env.OBS_AUTH_FAILURE_THRESHOLD, 10) || 10,
      sensorFailureCount: parseInt(process.env.OBS_SENSOR_FAILURE_THRESHOLD, 10) || 5,
      activeFlowPercent: parseFloat(process.env.OBS_ACTIVE_FLOW_THRESHOLD_PERCENT) || 80.0
    };
  }

  async checkAndTriggerIncident({ type, severity, source, message, metric, currentValue, threshold, requestId = null, metadata = {} }) {
    try {
      // Look for open or acknowledged incident of the same type and source to deduplicate
      let incident = await OperationalIncident.findOne({
        type,
        source,
        status: { $in: ['OPEN', 'ACKNOWLEDGED'] }
      });

      if (incident) {
        incident.occurrenceCount += 1;
        incident.lastDetectedAt = new Date();
        incident.currentValue = currentValue;
        if (requestId) incident.requestId = requestId;
        await incident.save();

        logger.info(`[OBSERVABILITY] Updated active operational incident '${type}' (occurrences: ${incident.occurrenceCount})`);
        eventPublisher.publishOperationalEvent('system.incident.updated', { incident }, requestId);
        return incident;
      }

      // Create new incident
      incident = await OperationalIncident.create({
        type,
        severity,
        source,
        message,
        metric,
        currentValue,
        threshold,
        requestId,
        metadata
      });

      logger.warn(`[OBSERVABILITY] Created NEW operational incident '${type}' (Severity: ${severity})`);
      eventPublisher.publishOperationalEvent('system.incident.created', { incident }, requestId);
      return incident;
    } catch (err) {
      logger.error(`[OBSERVABILITY ERROR] Failed to record operational incident: ${err.message}`);
      return null;
    }
  }

  async evaluateMetrics() {
    const summary = metricsCollector.getMetricsSummary();

    // 1. Check HTTP Error Rate
    if (summary.http.errorRatePercent >= this.thresholds.httpErrorRatePercent && summary.http.totalRequests > 10) {
      await this.checkAndTriggerIncident({
        type: 'HIGH_HTTP_ERROR_RATE',
        severity: 'HIGH',
        source: 'backend',
        message: `HTTP 5xx error rate reached ${summary.http.errorRatePercent}% (threshold: ${this.thresholds.httpErrorRatePercent}%)`,
        metric: 'http.errorRatePercent',
        currentValue: summary.http.errorRatePercent,
        threshold: this.thresholds.httpErrorRatePercent
      });
    }

    // 2. Check ML Inference Latency
    if (summary.ml.latency.p95 >= this.thresholds.mlLatencyMs && summary.ml.totalRequests > 5) {
      await this.checkAndTriggerIncident({
        type: 'HIGH_ML_INFERENCE_LATENCY',
        severity: 'MEDIUM',
        source: 'mlService',
        message: `FastAPI ML p95 inference latency reached ${summary.ml.latency.p95}ms (threshold: ${this.thresholds.mlLatencyMs}ms)`,
        metric: 'ml.latency.p95',
        currentValue: summary.ml.latency.p95,
        threshold: this.thresholds.mlLatencyMs
      });
    }

    // 3. Check Auth Failure Spikes
    const totalAuthFailures = (summary.auth.authFailures || 0) + (summary.auth.loginFailure || 0);
    if (totalAuthFailures >= this.thresholds.authFailureCount) {
      await this.checkAndTriggerIncident({
        type: 'AUTHENTICATION_FAILURE_SPIKE',
        severity: 'HIGH',
        source: 'auth',
        message: `Authentication failure count reached ${totalAuthFailures} (threshold: ${this.thresholds.authFailureCount})`,
        metric: 'auth.authFailures',
        currentValue: totalAuthFailures,
        threshold: this.thresholds.authFailureCount
      });
    }
  }
}

const operationalAlertEngine = new OperationalAlertEngine();
module.exports = operationalAlertEngine;
