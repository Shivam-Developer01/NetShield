/**
 * Host Telemetry (EDR) Service
 * Ingests and validates endpoint security telemetry events (failed logins, privilege escalation, suspicious processes).
 * Marked as: OPTIONAL / EXTERNAL ADAPTER READY.
 */

const correlationEngine = require('./correlationEngine');

class HostTelemetryService {
  /**
   * Processes an incoming host telemetry event and forwards to the correlation engine.
   * @param {Object} eventData
   * @returns {Promise<Object>} Processed event confirmation and any correlated incident
   */
  async ingestHostEvent(eventData) {
    const correlationPayload = {
      source: 'edr',
      src_ip: eventData.src_ip || '127.0.0.1',
      dst_ip: eventData.dst_ip || null,
      event_type: eventData.event_type,
      severity: eventData.severity || 'medium',
      host_id: eventData.host_id,
      user: eventData.user,
      process_name: eventData.process_name,
      timestamp: eventData.timestamp || new Date().toISOString()
    };

    const incident = await correlationEngine.ingestAndCorrelate(correlationPayload);

    return {
      status: 'ingested',
      telemetry_type: 'host_edr',
      event_type: eventData.event_type,
      correlated_incident_id: incident ? incident._id : null,
      timestamp: correlationPayload.timestamp
    };
  }

  /**
   * Returns current adapter status.
   */
  getStatus() {
    return {
      adapter_name: 'NetShield Host Telemetry Adapter (EDR)',
      status: 'READY_OPTIONAL',
      supported_events: [
        'failed_login',
        'privilege_escalation',
        'suspicious_process',
        'process_spawn',
        'file_write',
        'credential_access'
      ],
      active_connections: 0
    };
  }
}

module.exports = new HostTelemetryService();
