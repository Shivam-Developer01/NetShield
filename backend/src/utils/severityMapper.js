/**
 * Threat Severity & Alert Mapping Utility
 * Maps model prediction labels from NSL-KDD and CICIDS2017 to standardized threat severity levels.
 * Severity Levels: 'low', 'medium', 'high', 'critical'.
 */

const NSL_KDD_SEVERITY_MAP = {
  'Normal': { isAttack: false },
  'Probe': {
    isAttack: true,
    severity: 'low',
    description: 'Network reconnaissance or port scanning attempt detected (Probe).'
  },
  'R2L': {
    isAttack: true,
    severity: 'medium',
    description: 'Unauthorized remote access attempt detected (Remote-to-Local).'
  },
  'DoS': {
    isAttack: true,
    severity: 'high',
    description: 'Denial of Service attack traffic detected (DoS).'
  },
  'U2R': {
    isAttack: true,
    severity: 'critical',
    description: 'Unauthorized local superuser privilege escalation attempt detected (User-to-Root).'
  }
};

const CICIDS2017_SEVERITY_MAP = {
  'BENIGN': { isAttack: false },
  'Bot': {
    isAttack: true,
    severity: 'medium',
    description: 'Botnet command and control traffic detected (Bot).'
  },
  'PortScan': {
    isAttack: true,
    severity: 'medium',
    description: 'Network port scan activity detected (PortScan).'
  },
  'DoS Slowhttptest': {
    isAttack: true,
    severity: 'medium',
    description: 'Slow HTTP Denial of Service attack detected (DoS Slowhttptest).'
  },
  'DoS slowloris': {
    isAttack: true,
    severity: 'medium',
    description: 'Slowloris HTTP connection exhaustion attack detected (DoS slowloris).'
  },
  'DDoS': {
    isAttack: true,
    severity: 'high',
    description: 'Distributed Denial of Service attack traffic detected (DDoS).'
  },
  'DoS Hulk': {
    isAttack: true,
    severity: 'high',
    description: 'High-volume HTTP flood attack detected (DoS Hulk).'
  },
  'DoS GoldenEye': {
    isAttack: true,
    severity: 'high',
    description: 'GoldenEye HTTP DoS layer 7 attack detected (DoS GoldenEye).'
  },
  'FTP-Patator': {
    isAttack: true,
    severity: 'high',
    description: 'FTP brute force authentication attack detected (FTP-Patator).'
  },
  'SSH-Patator': {
    isAttack: true,
    severity: 'high',
    description: 'SSH brute force authentication attack detected (SSH-Patator).'
  },
  'Web Attack \ufffd Brute Force': {
    isAttack: true,
    severity: 'high',
    description: 'Web application credential brute force attack detected.'
  },
  'Web Attack - Brute Force': {
    isAttack: true,
    severity: 'high',
    description: 'Web application credential brute force attack detected.'
  },
  'Web Attack \ufffd XSS': {
    isAttack: true,
    severity: 'high',
    description: 'Cross-Site Scripting web application attack detected (XSS).'
  },
  'Web Attack - XSS': {
    isAttack: true,
    severity: 'high',
    description: 'Cross-Site Scripting web application attack detected (XSS).'
  },
  'Infiltration': {
    isAttack: true,
    severity: 'critical',
    description: 'Internal network infiltration / backdoor activity detected.'
  },
  'Heartbleed': {
    isAttack: true,
    severity: 'critical',
    description: 'OpenSSL Heartbleed memory disclosure exploit attempt detected.'
  },
  'Web Attack \ufffd Sql Injection': {
    isAttack: true,
    severity: 'critical',
    description: 'SQL Injection database exploit attempt detected.'
  },
  'Web Attack - Sql Injection': {
    isAttack: true,
    severity: 'critical',
    description: 'SQL Injection database exploit attempt detected.'
  }
};

/**
 * Evaluates a model prediction label and returns severity metadata.
 * @param {string} datasetType - 'nsl_kdd' | 'cicids2017'
 * @param {string} predictionLabel - Model prediction label
 * @returns {{ isAttack: boolean, severity?: string, description?: string, attackType?: string }}
 */
const mapPredictionToSeverity = (datasetType, predictionLabel) => {
  const cleanDataset = (datasetType || '').toLowerCase();
  const label = predictionLabel || '';

  if (cleanDataset === 'nsl_kdd') {
    const match = NSL_KDD_SEVERITY_MAP[label];
    if (match) {
      return { ...match, attackType: label };
    }
  } else if (cleanDataset === 'cicids2017') {
    const match = CICIDS2017_SEVERITY_MAP[label];
    if (match) {
      return { ...match, attackType: label };
    }
  }

  // Fallback for unknown prediction labels
  if (label === 'Normal' || label === 'BENIGN') {
    return { isAttack: false };
  }

  return {
    isAttack: true,
    severity: 'medium',
    attackType: label,
    description: `Suspicious intrusion traffic detected (${label}).`
  };
};

module.exports = {
  mapPredictionToSeverity,
  NSL_KDD_SEVERITY_MAP,
  CICIDS2017_SEVERITY_MAP
};
