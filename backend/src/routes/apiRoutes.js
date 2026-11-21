const express = require('express');
const router = express.Router();

const healthController = require('../controllers/healthController');
const predictionController = require('../controllers/predictionController');
const alertController = require('../controllers/alertController');
const metricController = require('../controllers/metricController');
const settingController = require('../controllers/settingController');

const authRoutes = require('./authRoutes');
const userRoutes = require('./userRoutes');
const analyticsRoutes = require('./analyticsRoutes');
const investigationRoutes = require('./investigationRoutes');
const operationalIncidentRoutes = require('./operationalIncidentRoutes');
const telemetryRoutes = require('./telemetryRoutes');

const authenticate = require('../middleware/authenticate');
const authorize = require('../middleware/authorize');

// 1. Auth routes (register, login, logout, me)
router.use('/auth', authRoutes);

// 2. User management routes (ADMIN only)
router.use('/users', userRoutes);

// 3. Analytics routes (/api/analytics)
router.use('/analytics', analyticsRoutes);

// 4. Investigation routes (/api/investigations)
router.use('/investigations', investigationRoutes);

// 5. Operations & Incident routes (/api/operations/incidents)
router.use('/operations/incidents', operationalIncidentRoutes);

// 5b. External Telemetry & Defense-in-Depth Adapters (/api/telemetry)
router.use('/telemetry', telemetryRoutes);

// 5. Health status check (Public endpoint for infrastructure probes)
router.get('/health', healthController.getHealthStatus);

// 6. Intrusion Prediction routes
router.post(
  '/predictions',
  authenticate,
  authorize('ADMIN', 'ANALYST', 'SERVICE'),
  predictionController.createPrediction
);
router.get(
  '/predictions',
  authenticate,
  authorize('ADMIN', 'ANALYST', 'VIEWER'),
  predictionController.getPredictions
);

// 7. Threat Alert management routes
router.get(
  '/alerts',
  authenticate,
  authorize('ADMIN', 'ANALYST', 'VIEWER'),
  alertController.getAlerts
);
router.get(
  '/alerts/:id',
  authenticate,
  authorize('ADMIN', 'ANALYST', 'VIEWER'),
  alertController.getAlertById
);
router.patch(
  '/alerts/:id',
  authenticate,
  authorize('ADMIN', 'ANALYST'),
  alertController.updateAlertStatus
);

// 8. System Telemetry & Metrics routes
router.get(
  '/metrics',
  authenticate,
  authorize('ADMIN', 'ANALYST', 'VIEWER'),
  metricController.getSystemMetrics
);

// 9. System Settings routes
router.get(
  '/settings',
  authenticate,
  authorize('ADMIN', 'ANALYST', 'VIEWER'),
  settingController.getSettings
);
router.patch(
  '/settings/:key',
  authenticate,
  authorize('ADMIN'),
  settingController.updateSettingByKey
);
router.post(
  '/settings/notify-digest',
  authenticate,
  authorize('ADMIN'),
  settingController.triggerDigestNotification
);
router.post(
  '/settings/test-email',
  authenticate,
  authorize('ADMIN'),
  settingController.sendTestEmail
);
router.get(
  '/settings/smtp-status',
  authenticate,
  authorize('ADMIN'),
  settingController.checkSmtpStatus
);

module.exports = router;
