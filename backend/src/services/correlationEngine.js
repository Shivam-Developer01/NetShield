/**
 * NetShield Phase 19.6 Multi-Signal Alert Correlation Engine
 * Ingests telemetry across Network Flow ML, External Network IDS, and Host EDR Telemetry.
 * Correlates events across a 5-minute sliding window and promotes multi-source attacks
 * to high-confidence Operational Incidents while deduplicating alert floods.
 */

const OperationalIncident = require('../models/OperationalIncident');
const { evaluateIncidentSeverity } = require('../utils/severityPolicy');
const logger = require('../utils/logger') || console;

class MultiSignalCorrelationEngine {
  constructor(windowMs = 300000) { // 5-minute correlation window
    this.windowMs = windowMs;
    this.events = []; // In-memory sliding window of recent telemetry events
  }

  /**
   * Prunes telemetry records older than windowMs.
   */
  pruneStaleEvents() {
    const cutoff = Date.now() - this.windowMs;
    this.events = this.events.filter(e => e.timestamp >= cutoff);
  }

  /**
   * Ingests a new telemetry signal and evaluates multi-source correlation.
   * @param {Object} event
   * @param {string} event.source - 'ml' | 'ids' | 'edr'
   * @param {string} event.src_ip - Source IP
   * @param {string} [event.dst_ip] - Destination IP
   * @param {string} [event.prediction] - ML Prediction label
   * @param {number} [event.confidence] - ML Confidence
   * @param {string} [event.signature] - IDS Signature name
   * @param {string} [event.event_type] - EDR Event Type (e.g. privilege_escalation)
   * @param {string} [event.severity] - Source-reported severity
   */
  async ingestAndCorrelate(event) {
    const now = Date.now();
    const enrichedEvent = {
      ...event,
      timestamp: event.timestamp ? new Date(event.timestamp).getTime() : now
    };

    this.events.push(enrichedEvent);
    this.pruneStaleEvents();

    const srcIp = enrichedEvent.src_ip;
    const dstIp = enrichedEvent.dst_ip;

    // Find all related events within the correlation window for this IP pair
    const related = this.events.filter(e => 
      (srcIp && (e.src_ip === srcIp || e.dst_ip === srcIp)) ||
      (dstIp && (e.dst_ip === dstIp || e.src_ip === dstIp))
    );

    const mlEvents = related.filter(e => e.source === 'ml');
    const idsEvents = related.filter(e => e.source === 'ids');
    const hostEvents = related.filter(e => e.source === 'edr');

    // If only a single source has events, no multi-source correlation is possible yet
    const sourcesCount = (mlEvents.length > 0 ? 1 : 0) + (idsEvents.length > 0 ? 1 : 0) + (hostEvents.length > 0 ? 1 : 0);

    if (sourcesCount >= 2) {
      // Multi-source correlation detected!
      const latestMl = mlEvents[mlEvents.length - 1];
      const severityContext = {
        mlPrediction: latestMl?.prediction || 'Unknown',
        mlConfidence: latestMl?.confidence || 0.8,
        idsAlerts: idsEvents,
        hostEvents: hostEvents
      };

      const evalResult = evaluateIncidentSeverity(severityContext);

      try {
        const incidentType = 'SECURITY_CORRELATED_INCIDENT';
        const incidentKey = `${srcIp || 'unknown'}->${dstIp || 'unknown'}`;

        let incident = await OperationalIncident.findOne({
          type: incidentType,
          status: 'OPEN',
          'metadata.targetPair': incidentKey
        });

        const incidentMessage = `Multi-Signal Security Incident: ${evalResult.rationale} [Sources: ${[...new Set(related.map(r => r.source.toUpperCase()))].join(', ')}]`;

        if (incident) {
          incident.occurrenceCount += 1;
          incident.lastDetectedAt = new Date();
          incident.severity = evalResult.severity;
          incident.message = incidentMessage;
          await incident.save();
          logger.warn?.(`[Correlation Engine] Updated incident ${incident._id} to ${evalResult.severity} (${incident.occurrenceCount} signals)`);
          return incident;
        } else {
          incident = await OperationalIncident.create({
            type: incidentType,
            severity: evalResult.severity,
            status: 'OPEN',
            source: 'correlation_engine',
            message: incidentMessage,
            occurrenceCount: 1,
            firstDetectedAt: new Date(),
            lastDetectedAt: new Date(),
            metadata: {
              targetPair: incidentKey,
              srcIp: srcIp || 'unknown',
              dstIp: dstIp || 'unknown',
              corroboratedSources: [...new Set(related.map(r => r.source))].join(','),
              signalCount: String(related.length)
            }
          });
          logger.warn?.(`[Correlation Engine] Created NEW multi-source incident ${incident._id} (${evalResult.severity})`);
          return incident;
        }
      } catch (err) {
        logger.error?.('[Correlation Engine] Failed to record correlated incident:', err);
      }
    }

    return null;
  }
}

const correlationEngineInstance = new MultiSignalCorrelationEngine();

module.exports = correlationEngineInstance;
