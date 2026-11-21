/**
 * NetShield Centralized Operational Metrics Collector
 * Collects in-process operational metrics for HTTP requests, Authentication,
 * ML Service IPC, Network Sensor telemetry, MongoDB queries, and Socket.IO connections.
 */

class MetricsCollector {
  constructor() {
    this.reset();
  }

  reset() {
    this.startTime = Date.now();
    this.httpRequestsTotal = 0;
    this.httpRequestsByStatus = { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 };
    this.httpRequestsByMethod = {};
    this.httpLatenciesMs = [];

    this.authStats = {
      loginSuccess: 0,
      loginFailure: 0,
      logoutCount: 0,
      registerCount: 0,
      rateLimitRejections: 0,
      csrfRejections: 0,
      authFailures: 0
    };

    this.mlStats = {
      inferenceRequestsTotal: 0,
      inferenceSuccess: 0,
      inferenceFailures: 0,
      inferenceLatenciesMs: [],
      datasetUsage: { nsl_kdd: 0, cicids2017: 0 },
      fallbackCount: 0
    };

    this.sensorStats = {
      packetsProcessed: 0,
      flowsCreated: 0,
      flowsExpired: 0,
      activeFlows: 0,
      validationFailures: 0,
      inferenceSubmissions: 0,
      failedSubmissions: 0,
      retryCount: 0,
      fallbackCount: 0,
      lastSeenAt: null
    };

    this.dbStats = {
      connectionState: 'disconnected',
      operationFailures: 0,
      queryLatenciesMs: []
    };

    this.socketStats = {
      activeConnections: 0,
      connectionAttempts: 0,
      authFailures: 0,
      disconnects: 0,
      reconnects: 0,
      publishedEvents: 0,
      failedPublications: 0
    };
  }

  recordHttpRequest(method, status, durationMs) {
    this.httpRequestsTotal++;
    this.httpRequestsByMethod[method] = (this.httpRequestsByMethod[method] || 0) + 1;

    const statusGroup = `${Math.floor(status / 100)}xx`;
    if (this.httpRequestsByStatus[statusGroup] !== undefined) {
      this.httpRequestsByStatus[statusGroup]++;
    }

    this.httpLatenciesMs.push(durationMs);
    if (this.httpLatenciesMs.length > 1000) {
      this.httpLatenciesMs.shift();
    }
  }

  recordAuthEvent(eventType) {
    if (this.authStats[eventType] !== undefined) {
      this.authStats[eventType]++;
    }
  }

  recordMlInference(success, datasetType, durationMs, isFallback = false) {
    this.mlStats.inferenceRequestsTotal++;
    if (success) {
      this.mlStats.inferenceSuccess++;
    } else {
      this.mlStats.inferenceFailures++;
    }

    const normalizedDataset = datasetType ? String(datasetType).toLowerCase().replace(/-/g, '_') : null;
    if (normalizedDataset && this.mlStats.datasetUsage[normalizedDataset] !== undefined) {
      this.mlStats.datasetUsage[normalizedDataset]++;
    }

    if (isFallback) {
      this.mlStats.fallbackCount++;
    }

    if (typeof durationMs === 'number') {
      this.mlStats.inferenceLatenciesMs.push(durationMs);
      if (this.mlStats.inferenceLatenciesMs.length > 1000) {
        this.mlStats.inferenceLatenciesMs.shift();
      }
    }
  }

  updateSensorTelemetry(telemetryData) {
    if (!telemetryData) return;
    const packets = telemetryData.packetsProcessed !== undefined ? telemetryData.packetsProcessed : telemetryData.packets_captured;
    if (packets !== undefined) this.sensorStats.packetsProcessed = packets;

    const flows = telemetryData.flowsCreated !== undefined ? telemetryData.flowsCreated : telemetryData.flows_generated;
    if (flows !== undefined) this.sensorStats.flowsCreated = flows;

    const active = telemetryData.activeFlows !== undefined ? telemetryData.activeFlows : telemetryData.active_flows;
    if (active !== undefined) this.sensorStats.activeFlows = active;

    const failures = telemetryData.validationFailures !== undefined ? telemetryData.validationFailures : telemetryData.flows_rejected;
    if (failures !== undefined) this.sensorStats.validationFailures = failures;

    this.sensorStats.retryCount += telemetryData.retryCount || 0;
    this.sensorStats.fallbackCount += telemetryData.fallbackCount || 0;
    this.sensorStats.lastSeenAt = new Date().toISOString();
  }

  recordDbQuery(success, durationMs) {
    if (!success) {
      this.dbStats.operationFailures++;
    }
    if (typeof durationMs === 'number') {
      this.dbStats.queryLatenciesMs.push(durationMs);
      if (this.dbStats.queryLatenciesMs.length > 500) {
        this.dbStats.queryLatenciesMs.shift();
      }
    }
  }

  recordSocketEvent(eventType) {
    if (eventType === 'connect') {
      this.socketStats.activeConnections++;
      this.socketStats.connectionAttempts++;
    } else if (eventType === 'disconnect') {
      this.socketStats.activeConnections = Math.max(0, this.socketStats.activeConnections - 1);
      this.socketStats.disconnects++;
    } else if (eventType === 'authFailure') {
      this.socketStats.authFailures++;
    } else if (eventType === 'publish') {
      this.socketStats.publishedEvents++;
    }
  }

  computePercentiles(arr) {
    if (!arr || arr.length === 0) {
      return { avg: 0, p50: 0, p95: 0, p99: 0 };
    }
    const sorted = [...arr].sort((a, b) => a - b);
    const len = sorted.length;
    const sum = sorted.reduce((acc, val) => acc + val, 0);
    const avg = Math.round(sum / len);
    const p50 = Math.round(sorted[Math.floor(len * 0.5)]);
    const p95 = Math.round(sorted[Math.min(Math.floor(len * 0.95), len - 1)]);
    const p99 = Math.round(sorted[Math.min(Math.floor(len * 0.99), len - 1)]);
    return { avg, p50, p95, p99 };
  }

  getMetricsSummary() {
    const httpLat = this.computePercentiles(this.httpLatenciesMs);
    const mlLat = this.computePercentiles(this.mlStats.inferenceLatenciesMs);
    const dbLat = this.computePercentiles(this.dbStats.queryLatenciesMs);

    const uptimeSeconds = Math.floor((Date.now() - this.startTime) / 1000);
    const errorRate = this.httpRequestsTotal > 0
      ? Number(((this.httpRequestsByStatus['5xx'] / this.httpRequestsTotal) * 100).toFixed(2))
      : 0;

    return {
      uptimeSeconds,
      http: {
        totalRequests: this.httpRequestsTotal,
        byStatus: this.httpRequestsByStatus,
        byMethod: this.httpRequestsByMethod,
        errorRatePercent: errorRate,
        latency: httpLat
      },
      auth: this.authStats,
      ml: {
        totalRequests: this.mlStats.inferenceRequestsTotal,
        successCount: this.mlStats.inferenceSuccess,
        failureCount: this.mlStats.inferenceFailures,
        fallbackCount: this.mlStats.fallbackCount,
        datasetUsage: this.mlStats.datasetUsage,
        latency: mlLat
      },
      sensor: this.sensorStats,
      db: {
        connectionState: this.dbStats.connectionState,
        operationFailures: this.dbStats.operationFailures,
        latency: dbLat
      },
      socket: this.socketStats
    };
  }

  getPrometheusFormat() {
    const s = this.getMetricsSummary();
    let lines = [];
    lines.push(`# HELP netshield_http_requests_total Total HTTP requests processed`);
    lines.push(`# TYPE netshield_http_requests_total counter`);
    lines.push(`netshield_http_requests_total ${s.http.totalRequests}`);

    lines.push(`# HELP netshield_http_errors_total Total 5xx HTTP errors`);
    lines.push(`# TYPE netshield_http_errors_total counter`);
    lines.push(`netshield_http_errors_total ${s.http.byStatus['5xx']}`);

    lines.push(`# HELP netshield_http_request_duration_ms_avg Average HTTP request duration in ms`);
    lines.push(`# TYPE netshield_http_request_duration_ms_avg gauge`);
    lines.push(`netshield_http_request_duration_ms_avg ${s.http.latency.avg}`);

    lines.push(`# HELP netshield_http_request_duration_ms_p95 p95 HTTP request duration in ms`);
    lines.push(`# TYPE netshield_http_request_duration_ms_p95 gauge`);
    lines.push(`netshield_http_request_duration_ms_p95 ${s.http.latency.p95}`);

    lines.push(`# HELP netshield_auth_failures_total Total authentication failures`);
    lines.push(`# TYPE netshield_auth_failures_total counter`);
    lines.push(`netshield_auth_failures_total ${s.auth.authFailures + s.auth.loginFailure}`);

    lines.push(`# HELP netshield_ml_inference_total Total ML inference requests`);
    lines.push(`# TYPE netshield_ml_inference_total counter`);
    lines.push(`netshield_ml_inference_total ${s.ml.totalRequests}`);

    lines.push(`# HELP netshield_ml_inference_errors_total Total ML inference failures`);
    lines.push(`# TYPE netshield_ml_inference_errors_total counter`);
    lines.push(`netshield_ml_inference_errors_total ${s.ml.failureCount}`);

    lines.push(`# HELP netshield_ml_inference_duration_ms_avg Average ML inference duration in ms`);
    lines.push(`# TYPE netshield_ml_inference_duration_ms_avg gauge`);
    lines.push(`netshield_ml_inference_duration_ms_avg ${s.ml.latency.avg}`);

    lines.push(`# HELP netshield_active_socket_connections Active WebSocket connections`);
    lines.push(`# TYPE netshield_active_socket_connections gauge`);
    lines.push(`netshield_active_socket_connections ${s.socket.activeConnections}`);

    lines.push(`# HELP netshield_sensor_packets_processed Total packets processed by sensor`);
    lines.push(`# TYPE netshield_sensor_packets_processed counter`);
    lines.push(`netshield_sensor_packets_processed ${s.sensor.packetsProcessed}`);

    return lines.join('\n') + '\n';
  }
}

const metricsCollector = new MetricsCollector();
module.exports = metricsCollector;
