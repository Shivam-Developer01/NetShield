const express = require('express');
const router = express.Router();
const controller = require('../controllers/operationalIncidentController');
const authenticate = require('../middleware/authenticate');
const authorize = require('../middleware/authorize');

// All incident endpoints require authentication
router.use(authenticate);

// View incidents (ADMIN, ANALYST, VIEWER)
router.get('/', authorize('ADMIN', 'ANALYST', 'VIEWER'), controller.getIncidents);
router.get('/:id', authorize('ADMIN', 'ANALYST', 'VIEWER'), controller.getIncidentById);

// Modify incident status (ADMIN, ANALYST only)
router.patch('/:id', authorize('ADMIN', 'ANALYST'), controller.updateIncidentStatus);

module.exports = router;
