const express = require('express');
const router = express.Router();
const investigationController = require('../controllers/investigationController');
const authenticate = require('../middleware/authenticate');
const authorize = require('../middleware/authorize');

router.use(authenticate);

// 1. Consolidated Alert Investigation Details
router.get(
  '/alerts/:id',
  authorize('ADMIN', 'ANALYST', 'VIEWER'),
  investigationController.getAlertInvestigation
);

// 2. Bounded Related Security Activity Feed
router.get(
  '/alerts/:id/activity',
  authorize('ADMIN', 'ANALYST', 'VIEWER'),
  investigationController.getRelatedActivity
);

module.exports = router;
