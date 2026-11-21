const Alert = require('../models/Alert');
const Log = require('../models/Log');

const getAlertInvestigation = async (alertId) => {
  const alert = await Alert.findById(alertId).lean();
  if (!alert) return null;

  // Find corresponding Log entry (matching datasetType & prediction around alert timestamp)
  const windowStart = new Date(alert.timestamp.getTime() - 5 * 60 * 1000);
  const windowEnd = new Date(alert.timestamp.getTime() + 5 * 60 * 1000);

  const relatedLog = await Log.findOne({
    datasetType: alert.datasetType,
    prediction: alert.prediction,
    timestamp: { $gte: windowStart, $lte: windowEnd }
  }).sort({ timestamp: -1 }).lean();

  // Construct Investigation Timeline (only include events that actually exist)
  const timeline = [];

  const baseTime = relatedLog ? relatedLog.timestamp : alert.timestamp;

  timeline.push({
    stage: 'PREDICTION_RECEIVED',
    label: 'Network Flow Data Received',
    timestamp: baseTime,
    details: { datasetType: alert.datasetType }
  });

  if (relatedLog && relatedLog.processingLatencyMs !== undefined) {
    timeline.push({
      stage: 'ML_INFERENCE',
      label: 'FastAPI XGBoost Inference Completed',
      timestamp: baseTime,
      details: {
        modelVersion: alert.modelVersion,
        processingLatencyMs: relatedLog.processingLatencyMs,
        confidence: alert.confidence
      }
    });
  }

  timeline.push({
    stage: 'PREDICTION_STORED',
    label: 'Prediction Log Persisted in MongoDB',
    timestamp: baseTime,
    details: { logId: relatedLog ? relatedLog._id : null }
  });

  timeline.push({
    stage: 'ALERT_CREATED',
    label: `Security Alert Triggered (${alert.severity.toUpperCase()})`,
    timestamp: alert.timestamp,
    details: {
      alertId: alert._id,
      severity: alert.severity,
      attackType: alert.attackType,
      status: alert.status
    }
  });

  if (alert.acknowledgedAt) {
    timeline.push({
      stage: 'ALERT_ACKNOWLEDGED',
      label: 'Alert Acknowledged by Analyst',
      timestamp: alert.acknowledgedAt,
      details: { status: 'acknowledged' }
    });
  }

  if (alert.resolvedAt) {
    timeline.push({
      stage: 'ALERT_RESOLVED',
      label: 'Alert Resolved & Closed',
      timestamp: alert.resolvedAt,
      details: { status: 'resolved' }
    });
  }

  // Count other related alerts for the same dataset and attack type
  const relatedAlertsCount = await Alert.countDocuments({
    _id: { $ne: alert._id },
    datasetType: alert.datasetType,
    attackType: alert.attackType
  });

  return {
    alert: {
      id: alert._id,
      timestamp: alert.timestamp,
      severity: alert.severity,
      attackType: alert.attackType,
      prediction: alert.prediction,
      confidence: alert.confidence,
      datasetType: alert.datasetType,
      modelVersion: alert.modelVersion,
      status: alert.status,
      description: alert.description,
      acknowledgedAt: alert.acknowledgedAt,
      resolvedAt: alert.resolvedAt
    },
    relatedLog: relatedLog ? {
      id: relatedLog._id,
      timestamp: relatedLog.timestamp,
      predictionIndex: relatedLog.predictionIndex,
      confidence: relatedLog.confidence,
      recordsProcessed: relatedLog.recordsProcessed || 1,
      processingLatencyMs: relatedLog.processingLatencyMs || 0,
      classProbabilities: relatedLog.classProbabilities || {}
    } : null,
    timeline,
    relatedAlertsCount
  };
};

const getRelatedActivity = async (alertId, timeWindowMinutes = 15) => {
  const alert = await Alert.findById(alertId).lean();
  if (!alert) return null;

  const windowMs = Math.min(Math.max(timeWindowMinutes, 1), 60) * 60 * 1000;
  const startTime = new Date(alert.timestamp.getTime() - windowMs);
  const endTime = new Date(alert.timestamp.getTime() + windowMs);

  const nearbyLogs = await Log.find({
    datasetType: alert.datasetType,
    timestamp: { $gte: startTime, $lte: endTime }
  })
  .sort({ timestamp: -1 })
  .limit(50)
  .lean();

  const nearbyAlerts = await Alert.find({
    _id: { $ne: alert._id },
    datasetType: alert.datasetType,
    timestamp: { $gte: startTime, $lte: endTime }
  })
  .sort({ timestamp: -1 })
  .limit(20)
  .lean();

  return {
    alertId: alert._id,
    timeWindowMinutes,
    windowStart: startTime,
    windowEnd: endTime,
    logs: nearbyLogs.map(l => ({
      id: l._id,
      timestamp: l.timestamp,
      prediction: l.prediction,
      confidence: l.confidence,
      datasetType: l.datasetType,
      processingLatencyMs: l.processingLatencyMs
    })),
    alerts: nearbyAlerts.map(a => ({
      id: a._id,
      timestamp: a.timestamp,
      severity: a.severity,
      attackType: a.attackType,
      prediction: a.prediction,
      status: a.status
    }))
  };
};

module.exports = {
  getAlertInvestigation,
  getRelatedActivity
};
