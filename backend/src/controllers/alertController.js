/**
 * Alert Controller
 * Handles GET /api/alerts (Paginated & filtered alerts), GET /api/alerts/:id,
 * and PATCH /api/alerts/:id (Status updates).
 */

const Alert = require('../models/Alert');
const { validateUpdateAlertStatus } = require('../validators/alertValidator');
const { publishAlertUpdated } = require('../realtime/eventPublisher');

const getAlerts = async (req, res, next) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || '1', 10));
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || '20', 10)));
    const skip = (page - 1) * limit;

    const filter = {};

    if (req.query.status) {
      filter.status = req.query.status;
    }

    if (req.query.severity) {
      filter.severity = req.query.severity;
    }

    if (req.query.datasetType) {
      filter.datasetType = req.query.datasetType;
    }

    if (req.query.attackType) {
      filter.attackType = req.query.attackType;
    }

    if (req.query.startDate || req.query.endDate) {
      filter.timestamp = {};
      if (req.query.startDate) {
        filter.timestamp.$gte = new Date(req.query.startDate);
      }
      if (req.query.endDate) {
        filter.timestamp.$lte = new Date(req.query.endDate);
      }
    }

    const [total, data] = await Promise.all([
      Alert.countDocuments(filter),
      Alert.find(filter).sort({ timestamp: -1 }).skip(skip).limit(limit).lean()
    ]);

    const totalPages = Math.ceil(total / limit) || 1;

    res.status(200).json({
      success: true,
      pagination: {
        total,
        page,
        limit,
        totalPages
      },
      data
    });
  } catch (error) {
    next(error);
  }
};

const getAlertById = async (req, res, next) => {
  try {
    const alert = await Alert.findById(req.params.id).lean();
    if (!alert) {
      const error = new Error(`Alert not found with id: ${req.params.id}`);
      error.statusCode = 404;
      throw error;
    }

    res.status(200).json({
      success: true,
      data: alert
    });
  } catch (error) {
    next(error);
  }
};

const updateAlertStatus = async (req, res, next) => {
  try {
    const validated = validateUpdateAlertStatus(req.body);
    const { status } = validated;

    // Fetch existing alert to know previous status
    const previousAlert = await Alert.findById(req.params.id).lean();
    if (!previousAlert) {
      const error = new Error(`Alert not found with id: ${req.params.id}`);
      error.statusCode = 404;
      throw error;
    }

    const updateFields = { status };

    if (status === 'acknowledged') {
      updateFields.acknowledgedAt = new Date();
    } else if (status === 'resolved') {
      updateFields.resolvedAt = new Date();
    }

    const alert = await Alert.findByIdAndUpdate(
      req.params.id,
      { $set: updateFields },
      { new: true, runValidators: true }
    ).lean();

    // Broadcast Real-Time Alert Update Event
    const reqId = req.id || req.headers['x-request-id'];
    publishAlertUpdated({
      id: alert._id,
      previousStatus: previousAlert.status,
      status: alert.status,
      severity: alert.severity,
      attackType: alert.attackType,
      prediction: alert.prediction,
      datasetType: alert.datasetType,
      acknowledgedAt: alert.acknowledgedAt,
      resolvedAt: alert.resolvedAt,
      updatedBy: req.user ? req.user.email : 'system'
    }, reqId);

    res.status(200).json({
      success: true,
      data: alert
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  getAlerts,
  getAlertById,
  updateAlertStatus
};
