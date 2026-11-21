const { PREDICTION_CREATED, ALERT_CREATED, ALERT_UPDATED, METRICS_UPDATED, SYSTEM_HEALTH, SYSTEM_NOTIFICATION, ROOMS } = require('./eventTypes');
const logger = require('../utils/logger');
const { v4: uuidv4 } = require('crypto');

let ioInstance = null;

/**
 * Binds Socket.IO server instance to event publisher
 */
const setIO = (io) => {
  ioInstance = io;
};

/**
 * Returns active Socket.IO server instance
 */
const getIO = () => ioInstance;

/**
 * Recursively redacts credentials and secrets from event data
 */
const sanitizePayload = (obj) => {
  if (!obj || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(sanitizePayload);

  const clean = {};
  const sensitiveKeys = ['password', 'passwordhash', 'token', 'jwtsecret', 'csrftoken', 'authorization', 'cookie', 'mongouri', 'secret'];

  for (const [key, value] of Object.entries(obj)) {
    if (sensitiveKeys.includes(key.toLowerCase())) {
      continue; // Omit sensitive keys entirely
    }
    if (value && typeof value === 'object') {
      clean[key] = sanitizePayload(value);
    } else {
      clean[key] = value;
    }
  }
  return clean;
};

/**
 * Creates standardized real-time event envelope
 */
const createEnvelope = (eventType, data, requestId = null) => {
  return {
    event: eventType,
    timestamp: new Date().toISOString(),
    requestId: requestId || (data && data.requestId) || (crypto.randomUUID ? crypto.randomUUID() : `evt-${Date.now()}`),
    data: sanitizePayload(data)
  };
};

/**
 * Publishes prediction.created event to Analysts & Admins (soc:analysts room)
 */
const publishPredictionCreated = (data, requestId = null) => {
  if (!ioInstance) return;
  try {
    const envelope = createEnvelope(PREDICTION_CREATED, data, requestId);
    ioInstance.to(ROOMS.ANALYSTS).emit(PREDICTION_CREATED, envelope);
    logger.debug(`[EventPublisher] Broadcasted ${PREDICTION_CREATED} [req:${envelope.requestId}]`);
  } catch (error) {
    logger.error(`[EventPublisher] Error publishing ${PREDICTION_CREATED}: ${error.message}`);
  }
};

/**
 * Publishes alert.created event to Viewers, Analysts & Admins (soc:viewers room)
 */
const publishAlertCreated = (data, requestId = null) => {
  if (!ioInstance) return;
  try {
    const envelope = createEnvelope(ALERT_CREATED, data, requestId);
    ioInstance.to(ROOMS.VIEWERS).emit(ALERT_CREATED, envelope);
    logger.debug(`[EventPublisher] Broadcasted ${ALERT_CREATED} [req:${envelope.requestId}]`);
  } catch (error) {
    logger.error(`[EventPublisher] Error publishing ${ALERT_CREATED}: ${error.message}`);
  }
};

/**
 * Publishes alert.updated event to Viewers, Analysts & Admins (soc:viewers room)
 */
const publishAlertUpdated = (data, requestId = null) => {
  if (!ioInstance) return;
  try {
    const envelope = createEnvelope(ALERT_UPDATED, data, requestId);
    ioInstance.to(ROOMS.VIEWERS).emit(ALERT_UPDATED, envelope);
    logger.debug(`[EventPublisher] Broadcasted ${ALERT_UPDATED} [req:${envelope.requestId}]`);
  } catch (error) {
    logger.error(`[EventPublisher] Error publishing ${ALERT_UPDATED}: ${error.message}`);
  }
};

/**
 * Publishes metrics.updated event to Viewers, Analysts & Admins (soc:viewers room)
 */
const publishMetricsUpdated = (data, requestId = null) => {
  if (!ioInstance) return;
  try {
    const envelope = createEnvelope(METRICS_UPDATED, data, requestId);
    ioInstance.to(ROOMS.VIEWERS).emit(METRICS_UPDATED, envelope);
    logger.debug(`[EventPublisher] Broadcasted ${METRICS_UPDATED} [req:${envelope.requestId}]`);
  } catch (error) {
    logger.error(`[EventPublisher] Error publishing ${METRICS_UPDATED}: ${error.message}`);
  }
};

/**
 * Publishes system.health event to Viewers, Analysts & Admins (soc:viewers room)
 */
const publishSystemHealth = (data, requestId = null) => {
  if (!ioInstance) return;
  try {
    const envelope = createEnvelope(SYSTEM_HEALTH, data, requestId);
    ioInstance.to(ROOMS.VIEWERS).emit(SYSTEM_HEALTH, envelope);
    logger.debug(`[EventPublisher] Broadcasted ${SYSTEM_HEALTH} [req:${envelope.requestId}]`);
  } catch (error) {
    logger.error(`[EventPublisher] Error publishing ${SYSTEM_HEALTH}: ${error.message}`);
  }
};

/**
 * Publishes system.notification event to specified target room
 */
const publishSystemNotification = (data, targetRoom = ROOMS.VIEWERS, requestId = null) => {
  if (!ioInstance) return;
  try {
    const envelope = createEnvelope(SYSTEM_NOTIFICATION, data, requestId);
    ioInstance.to(targetRoom).emit(SYSTEM_NOTIFICATION, envelope);
    logger.debug(`[EventPublisher] Broadcasted ${SYSTEM_NOTIFICATION} to ${targetRoom}`);
  } catch (error) {
    logger.error(`[EventPublisher] Error publishing ${SYSTEM_NOTIFICATION}: ${error.message}`);
  }
};

/**
 * Publishes operational event (system.health.changed, system.incident.created, etc.)
 */
const publishOperationalEvent = (eventType, data, requestId = null) => {
  if (!ioInstance) return;
  try {
    const metricsCollector = require('../utils/metricsCollector');
    const envelope = createEnvelope(eventType, data, requestId);
    ioInstance.to(ROOMS.VIEWERS).emit(eventType, envelope);
    metricsCollector.recordSocketEvent('publish');
    logger.debug(`[EventPublisher] Broadcasted operational event ${eventType} [req:${envelope.requestId}]`);
  } catch (error) {
    logger.error(`[EventPublisher] Error publishing operational event ${eventType}: ${error.message}`);
  }
};

module.exports = {
  setIO,
  getIO,
  sanitizePayload,
  createEnvelope,
  publishPredictionCreated,
  publishAlertCreated,
  publishAlertUpdated,
  publishMetricsUpdated,
  publishSystemHealth,
  publishSystemNotification,
  publishOperationalEvent,
};
