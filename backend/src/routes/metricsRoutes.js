const express = require('express');
const router = express.Router();
const metricsController = require('../controllers/metricsController');

// GET /metrics returns Prometheus format
router.get('/', metricsController.getMetricsPrometheus);
// GET /metrics/json returns JSON summary
router.get('/json', metricsController.getMetricsJSON);

module.exports = router;
