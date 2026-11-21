const express = require('express');
const router = express.Router();
const telemetryController = require('../controllers/telemetryController');
const authenticate = require('../middleware/authenticate');
const authorize = require('../middleware/authorize');

router.use(authenticate);

// 1. Ingest Host EDR Event
router.post(
  '/host',
  authorize('ADMIN', 'ANALYST'),
  telemetryController.ingestHostTelemetry
);

// 2. Ingest Network IDS Signature Alert
router.post(
  '/ids',
  authorize('ADMIN', 'ANALYST'),
  telemetryController.ingestIdsTelemetry
);

// 3. Telemetry Status
router.get(
  '/status',
  authorize('ADMIN', 'ANALYST', 'VIEWER'),
  telemetryController.getTelemetryStatus
);

module.exports = router;
