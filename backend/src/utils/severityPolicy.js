/**
 * NetShield Phase 19.6 Evidence-Based Severity & Confidence Policy
 * Computes operational incident and alert severity based on multi-source evidence:
 * - Machine Learning Flow Inference (Volumetric & Statistical)
 * - Network IDS / DPI Signatures (Suricata, Snort, Zeek)
 * - Host Telemetry / EDR Events (Auditd, Falco, Sysmon)
 */

/**
 * Evaluates the multi-source severity level.
 * @param {Object} context - Evidence evaluation context
 * @param {string} [context.mlPrediction] - ML class prediction (e.g., 'DoS Hulk', 'R2L', 'Normal', 'BENIGN')
 * @param {number} [context.mlConfidence] - ML model confidence score [0.0 - 1.0]
 * @param {boolean} [context.isSuspicious] - Whether flow is flagged as suspicious/uncertain
 * @param {Array<Object>} [context.idsAlerts] - Correlated IDS signature alerts
 * @param {Array<Object>} [context.hostEvents] - Correlated Host EDR events
 * @returns {Object} { severity: 'low'|'medium'|'high'|'critical', rationale: string, confidenceScore: number }
 */
function evaluateIncidentSeverity(context = {}) {
  const {
    mlPrediction = 'Normal',
    mlConfidence = 0.5,
    isSuspicious = false,
    idsAlerts = [],
    hostEvents = []
  } = context;

  const hasHighHostEvent = hostEvents.some(e => 
    ['privilege_escalation', 'root_shell', 'credential_access', 'process_injection'].includes(e.event_type)
  );

  const hasFailedLoginBurst = hostEvents.filter(e => e.event_type === 'failed_login').length >= 3;

  const hasCriticalIds = idsAlerts.some(a => 
    a.severity === 'critical' || (a.signature && a.signature.toLowerCase().includes('exploit'))
  );

  const hasIdsMatch = idsAlerts.length > 0;
  const isMlMalicious = mlPrediction !== 'Normal' && mlPrediction !== 'BENIGN' && mlPrediction !== 'Unknown_-1';

  // 1. CRITICAL: Multiple independent corroborated signals or confirmed root compromise
  if ((isMlMalicious && hasHighHostEvent) || (isMlMalicious && hasCriticalIds) || (hasHighHostEvent && hasCriticalIds)) {
    return {
      severity: 'CRITICAL',
      rationale: 'Multiple independent telemetry sources corroborated critical exploit activity (ML Flow + EDR/IDS).',
      confidenceScore: Math.min(1.0, Math.max(mlConfidence, 0.95))
    };
  }

  // 2. HIGH: Volumetric attack OR single ML attack with matching IDS signature OR high-frequency brute force
  if (
    ['DDoS', 'DoS Hulk', 'DoS GoldenEye', 'U2R'].includes(mlPrediction) ||
    (isMlMalicious && hasIdsMatch) ||
    (isMlMalicious && hasFailedLoginBurst) ||
    hasHighHostEvent
  ) {
    return {
      severity: 'HIGH',
      rationale: 'Corroborated network intrusion alert or high-impact volumetric attack detected.',
      confidenceScore: Math.min(1.0, Math.max(mlConfidence, 0.85))
    };
  }

  // 3. MEDIUM: Single ML attack detection with moderate confidence OR single IDS signature
  if (isMlMalicious && mlConfidence >= 0.50) {
    return {
      severity: 'MEDIUM',
      rationale: `Statistical ML flow anomaly detected (${mlPrediction}) without endpoint corroboration.`,
      confidenceScore: mlConfidence
    };
  }

  // 4. LOW: Low-confidence ML prediction, suspicious traffic anomaly, or isolated failed login
  if (isSuspicious || (isMlMalicious && mlConfidence < 0.50) || idsAlerts.length > 0 || hostEvents.length > 0) {
    return {
      severity: 'LOW',
      rationale: 'Isolated suspicious network or host anomaly observed. Awaiting further telemetry correlation.',
      confidenceScore: Math.max(mlConfidence, 0.35)
    };
  }

  return {
    severity: 'LOW',
    rationale: 'Nominal traffic pattern.',
    confidenceScore: mlConfidence
  };
}

module.exports = {
  evaluateIncidentSeverity
};
