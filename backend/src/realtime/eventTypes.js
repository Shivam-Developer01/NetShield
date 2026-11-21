/**
 * NetShield Phase 14 — Real-Time SOC Event Types & Room Definitions
 */

module.exports = {
  PREDICTION_CREATED: 'prediction.created',
  ALERT_CREATED: 'alert.created',
  ALERT_UPDATED: 'alert.updated',
  METRICS_UPDATED: 'metrics.updated',
  SYSTEM_HEALTH: 'system.health',
  SYSTEM_NOTIFICATION: 'system.notification',

  ROOMS: {
    ADMINS: 'soc:admins',
    ANALYSTS: 'soc:analysts',
    VIEWERS: 'soc:viewers',
  },

  ROLES: {
    ADMIN: 'ADMIN',
    ANALYST: 'ANALYST',
    VIEWER: 'VIEWER',
  },
};
