const express = require('express');
const router = express.Router();
const analyticsController = require('../controllers/analyticsController');
const authenticate = require('../middleware/authenticate');
const authorize = require('../middleware/authorize');

router.use(authenticate);

// 1. Overview Analytics
router.get(
  '/overview',
  authorize('ADMIN', 'ANALYST', 'VIEWER'),
  analyticsController.getOverview
);

// 2. Trend Analytics
router.get(
  '/trends',
  authorize('ADMIN', 'ANALYST', 'VIEWER'),
  analyticsController.getTrends
);

// 3. Attack Distribution
router.get(
  '/attacks',
  authorize('ADMIN', 'ANALYST', 'VIEWER'),
  analyticsController.getAttacks
);

// 4. Severity Distribution
router.get(
  '/severity',
  authorize('ADMIN', 'ANALYST', 'VIEWER'),
  analyticsController.getSeverity
);

// 5. Dataset / Model Analytics
router.get(
  '/models',
  authorize('ADMIN', 'ANALYST', 'VIEWER'),
  analyticsController.getModels
);

// 5b. Model Information & Provenance
router.get(
  '/model-info',
  authorize('ADMIN', 'ANALYST', 'VIEWER'),
  analyticsController.getModelInfo
);

// 6. Alert Metrics
router.get(
  '/alerts',
  authorize('ADMIN', 'ANALYST', 'VIEWER'),
  analyticsController.getAlerts
);

// 7. CSV Export (ADMIN & ANALYST only)
router.get(
  '/export',
  authorize('ADMIN', 'ANALYST'),
  analyticsController.exportData
);

module.exports = router;
