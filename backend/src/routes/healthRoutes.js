const express = require('express');
const router = express.Router();
const healthController = require('../controllers/healthController');

router.get('/live', healthController.getLiveness);
router.get('/ready', healthController.getReadiness);
router.get('/', healthController.getHealthStatus);

module.exports = router;
