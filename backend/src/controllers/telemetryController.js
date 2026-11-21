/**
 * Telemetry Controller
 * Handles external telemetry ingestion for Host EDR and Network IDS adapters.
 */

const hostTelemetryService = require('../services/hostTelemetryService');
const idsTelemetryService = require('../services/idsTelemetryService');
const { logAuditEvent } = require('../utils/auditLogger');

const ingestHostTelemetry = async (req, res, next) => {
  try {
    const { event_type, host_id } = req.body;
    if (!event_type || !host_id) {
      return res.status(400).json({
        success: false,
        message: "Missing required fields: 'event_type' and 'host_id' are mandatory."
      });
    }

    const result = await hostTelemetryService.ingestHostEvent(req.body);
    logAuditEvent('TELEMETRY_INGEST', { details: { type: 'host_edr', event_type, host_id } }, req);

    res.status(200).json({
      success: true,
      data: result
    });
  } catch (err) {
    next(err);
  }
};

const ingestIdsTelemetry = async (req, res, next) => {
  try {
    const { signature, src_ip, dst_ip } = req.body;
    if (!signature || !src_ip || !dst_ip) {
      return res.status(400).json({
        success: false,
        message: "Missing required fields: 'signature', 'src_ip', and 'dst_ip' are mandatory."
      });
    }

    const result = await idsTelemetryService.ingestIdsAlert(req.body);
    logAuditEvent('TELEMETRY_INGEST', { details: { type: 'network_ids', signature, src_ip, dst_ip } }, req);

    res.status(200).json({
      success: true,
      data: result
    });
  } catch (err) {
    next(err);
  }
};

const getTelemetryStatus = async (req, res, next) => {
  try {
    res.status(200).json({
      success: true,
      data: {
        network_flow_ml: {
          name: 'NetShield Network Wire Sensor & ML Inference',
          status: 'CONNECTED_ACTIVE',
          data_plane: 'Live Packet / Flow Telemetry'
        },
        host_edr: hostTelemetryService.getStatus(),
        network_ids: idsTelemetryService.getStatus()
      }
    });
  } catch (err) {
    next(err);
  }
};

module.exports = {
  ingestHostTelemetry,
  ingestIdsTelemetry,
  getTelemetryStatus
};
