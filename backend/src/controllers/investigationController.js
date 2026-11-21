const investigationService = require('../services/investigationService');
const { validateActivityQuery } = require('../validators/analyticsValidator');
const { logAuditEvent } = require('../utils/auditLogger');

const getAlertInvestigation = async (req, res, next) => {
  try {
    const { id } = req.params;
    const data = await investigationService.getAlertInvestigation(id);

    if (!data) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'NOT_FOUND',
          message: `Alert with ID '${id}' not found.`
        }
      });
    }

    logAuditEvent('INVESTIGATION_VIEWED', { details: { alertId: id, severity: data.alert.severity } }, req);

    res.status(200).json({
      success: true,
      data
    });
  } catch (err) {
    next(err);
  }
};

const getRelatedActivity = async (req, res, next) => {
  try {
    const { id } = req.params;
    const { timeWindowMinutes } = validateActivityQuery(req.query);

    const data = await investigationService.getRelatedActivity(id, timeWindowMinutes);

    if (!data) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'NOT_FOUND',
          message: `Alert with ID '${id}' not found.`
        }
      });
    }

    res.status(200).json({
      success: true,
      data
    });
  } catch (err) {
    next(err);
  }
};

module.exports = {
  getAlertInvestigation,
  getRelatedActivity
};
