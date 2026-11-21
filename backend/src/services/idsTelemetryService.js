/**
 * Network IDS / DPI Telemetry Service
 * Ingests external network IDS / DPI signature alerts (Suricata, Snort, Zeek).
 * Marked as: OPTIONAL / EXTERNAL ADAPTER READY.
 */

const correlationEngine = require('./correlationEngine');

class IDSTelemetryService {
  /**
   * Processes an incoming IDS / DPI signature alert and forwards to the correlation engine.
   * @param {Object} alertData
   * @returns {Promise<Object>} Processed alert confirmation and any correlated incident
   */
  async ingestIdsAlert(alertData) {
    const correlationPayload = {
      source: 'ids',
      src_ip: alertData.src_ip,
      dst_ip: alertData.dst_ip,
      src_port: alertData.src_port || null,
      dst_port: alertData.dst_port || null,
      protocol: alertData.protocol || 'tcp',
      signature: alertData.signature,
      category: alertData.category || 'Exploit',
      severity: (alertData.severity || 'medium').toLowerCase(),
      timestamp: alertData.timestamp || new Date().toISOString()
    };

    const incident = await correlationEngine.ingestAndCorrelate(correlationPayload);

    return {
      status: 'ingested',
      telemetry_type: 'network_ids',
      signature: alertData.signature,
      correlated_incident_id: incident ? incident._id : null,
      timestamp: correlationPayload.timestamp
    };
  }

  /**
   * Returns current adapter status.
   */
  getStatus() {
    return {
      adapter_name: 'NetShield Network IDS / DPI Adapter (Suricata/Snort/Zeek)',
      status: 'READY_OPTIONAL',
      supported_engines: ['Suricata EVE-JSON', 'Snort 3', 'Zeek Notice/Conn'],
      active_connections: 0
    };
  }
}

module.exports = new IDSTelemetryService();
