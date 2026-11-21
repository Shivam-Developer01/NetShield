const analyticsService = require('../services/analyticsService');
const {
  validateAnalyticsQuery,
  validateTrendsQuery,
  validateExportQuery
} = require('../validators/analyticsValidator');
const { logAuditEvent } = require('../utils/auditLogger');

const getOverview = async (req, res, next) => {
  try {
    const query = validateAnalyticsQuery(req.query);
    const data = await analyticsService.getOverview(query);

    logAuditEvent('ANALYTICS_QUERY', { details: { endpoint: '/api/analytics/overview', query } }, req);

    res.status(200).json({
      success: true,
      ...data
    });
  } catch (err) {
    next(err);
  }
};

const getTrends = async (req, res, next) => {
  try {
    const query = validateTrendsQuery(req.query);
    const result = await analyticsService.getTrends(query);

    logAuditEvent('ANALYTICS_QUERY', { details: { endpoint: '/api/analytics/trends', interval: result.interval } }, req);

    res.status(200).json({
      success: true,
      ...result
    });
  } catch (err) {
    next(err);
  }
};

const getAttacks = async (req, res, next) => {
  try {
    const query = validateAnalyticsQuery(req.query);
    const data = await analyticsService.getAttacks(query);

    logAuditEvent('ANALYTICS_QUERY', { details: { endpoint: '/api/analytics/attacks' } }, req);

    res.status(200).json({
      success: true,
      data
    });
  } catch (err) {
    next(err);
  }
};

const getSeverity = async (req, res, next) => {
  try {
    const query = validateAnalyticsQuery(req.query);
    const data = await analyticsService.getSeverity(query);

    logAuditEvent('ANALYTICS_QUERY', { details: { endpoint: '/api/analytics/severity' } }, req);

    res.status(200).json({
      success: true,
      data
    });
  } catch (err) {
    next(err);
  }
};

const getModels = async (req, res, next) => {
  try {
    const query = validateAnalyticsQuery(req.query);
    const data = await analyticsService.getModels(query);

    logAuditEvent('ANALYTICS_QUERY', { details: { endpoint: '/api/analytics/models' } }, req);

    res.status(200).json({
      success: true,
      data
    });
  } catch (err) {
    next(err);
  }
};

const getAlerts = async (req, res, next) => {
  try {
    const query = validateAnalyticsQuery(req.query);
    const data = await analyticsService.getAlertAnalytics(query);

    logAuditEvent('ANALYTICS_QUERY', { details: { endpoint: '/api/analytics/alerts' } }, req);

    res.status(200).json({
      success: true,
      data
    });
  } catch (err) {
    next(err);
  }
};

const exportData = async (req, res, next) => {
  try {
    const query = validateExportQuery(req.query);
    const csv = await analyticsService.exportData(query);

    logAuditEvent('DATA_EXPORT', { details: { exportType: query.type, limit: query.limit } }, req);

    const filename = `netshield_${query.type}_export_${Date.now()}.csv`;
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.status(200).send(csv);
  } catch (err) {
    next(err);
  }
};

const mlService = require('../services/mlService');

const getModelInfo = async (req, res, next) => {
  try {
    const data = await mlService.getModelInfo(req.headers['x-request-id']);
    logAuditEvent('ANALYTICS_QUERY', { details: { endpoint: '/api/analytics/model-info' } }, req);
    res.status(200).json({
      success: true,
      ...data
    });
  } catch (err) {
    next(err);
  }
};

module.exports = {
  getOverview,
  getTrends,
  getAttacks,
  getSeverity,
  getModels,
  getModelInfo,
  getAlerts,
  exportData
};
