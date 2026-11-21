const OperationalIncident = require('../models/OperationalIncident');
const { incidentQuerySchema, incidentUpdateSchema } = require('../validators/operationalIncidentValidator');
const eventPublisher = require('../realtime/eventPublisher');
const logger = require('../utils/logger');

exports.getIncidents = async (req, res) => {
  try {
    const parseResult = incidentQuerySchema.safeParse(req.query);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        error: { code: 'INVALID_QUERY', details: parseResult.error.issues }
      });
    }

    const { status, severity, source, page, limit } = parseResult.data;
    const filter = {};
    if (status) filter.status = status;
    if (severity) filter.severity = severity;
    if (source) filter.source = source;

    const skip = (page - 1) * limit;
    const [incidents, total] = await Promise.all([
      OperationalIncident.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit),
      OperationalIncident.countDocuments(filter)
    ]);

    return res.status(200).json({
      success: true,
      data: incidents,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    logger.error(`[INCIDENT CONTROLLER] Error fetching incidents: ${err.message}`);
    return res.status(500).json({ success: false, error: { message: 'Failed to fetch operational incidents' } });
  }
};

exports.getIncidentById = async (req, res) => {
  try {
    const incident = await OperationalIncident.findById(req.params.id);
    if (!incident) {
      return res.status(404).json({ success: false, error: { message: 'Operational incident not found' } });
    }
    return res.status(200).json({ success: true, data: incident });
  } catch (err) {
    return res.status(500).json({ success: false, error: { message: 'Error retrieving incident' } });
  }
};

exports.updateIncidentStatus = async (req, res) => {
  try {
    const parseResult = incidentUpdateSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        error: { code: 'VALIDATION_ERROR', details: parseResult.error.issues }
      });
    }

    const { status, notes } = parseResult.data;
    const incident = await OperationalIncident.findById(req.params.id);
    if (!incident) {
      return res.status(404).json({ success: false, error: { message: 'Operational incident not found' } });
    }

    if (incident.status === 'RESOLVED' && status !== 'RESOLVED') {
      return res.status(400).json({
        success: false,
        error: { message: `Invalid status transition from RESOLVED to ${status}. Resolved incidents cannot be reopened.` }
      });
    }

    incident.status = status;
    if (status === 'RESOLVED' && !incident.resolvedAt) {
      incident.resolvedAt = new Date();
    }
    if (notes) {
      incident.metadata.set('resolutionNotes', notes);
    }

    await incident.save();

    logger.info(`[INCIDENT CONTROLLER] Incident ${incident._id} status updated to ${status} by user ${req.user ? req.user.id : 'system'}`);
    eventPublisher.publishOperationalEvent('system.incident.updated', { incident }, req.id);

    return res.status(200).json({ success: true, data: incident });
  } catch (err) {
    logger.error(`[INCIDENT CONTROLLER] Error updating incident status: ${err.message}`);
    return res.status(500).json({ success: false, error: { message: 'Failed to update operational incident' } });
  }
};
