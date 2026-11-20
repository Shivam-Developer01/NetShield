import React from 'react';
import { AlertCircle, AlertTriangle, Info, ShieldAlert, ShieldCheck } from 'lucide-react';

// Attack to severity taxonomy mapping aligned with backend severityMapper.js
const ATTACK_SEVERITY_MAP = {
  // Critical
  'u2r': 'critical',
  'buffer_overflow': 'critical',
  'loadmodule': 'critical',
  'rootkit': 'critical',
  'perl': 'critical',
  'multihop': 'critical',
  'guess_passwd': 'critical',
  'infiltration': 'critical',
  'heartbleed': 'critical',
  'web attack - sql injection': 'critical',
  'web attack  sql injection': 'critical',

  // High
  'dos': 'high',
  'ddos': 'high',
  'neptune': 'high',
  'smurf': 'high',
  'back': 'high',
  'satan': 'high',
  'ftp_write': 'high',
  'phf': 'high',
  'spy': 'high',
  'warezmaster': 'high',
  'dos hulk': 'high',
  'dos goldeneye': 'high',
  'ftp-patator': 'high',
  'ssh-patator': 'high',
  'bot': 'high',
  'web attack - brute force': 'high',
  'web attack  brute force': 'high',
  'web attack - xss': 'high',
  'web attack  xss': 'high',

  // Medium
  'probe': 'medium',
  'r2l': 'medium',
  'pod': 'medium',
  'teardrop': 'medium',
  'land': 'medium',
  'ipsweep': 'medium',
  'portsweep': 'medium',
  'nmap': 'medium',
  'warezclient': 'medium',
  'portscan': 'medium',
  'dos slowloris': 'medium',
  'dos slowhttptest': 'medium'
};

const SeverityBadge = ({ severity, prediction, isBenign, label }) => {
  const rawValue = prediction || label || severity || '';
  const cleanVal = String(rawValue).trim();
  const lowerVal = cleanVal.toLowerCase();

  // 1. Benign classification (Normal, BENIGN, clean, etc.)
  if (isBenign || lowerVal === 'benign' || cleanVal === 'Normal' || cleanVal === 'BENIGN' || lowerVal === 'clean') {
    const text = (cleanVal && cleanVal !== 'benign' && cleanVal !== 'clean') ? cleanVal : 'Benign';
    return (
      <span className="badge badge-benign" title={cleanVal || 'Benign'}>
        <ShieldCheck size={12} />
        {text}
      </span>
    );
  }

  // 2. Determine severity level: direct severity level or mapped from attack name
  let level = 'low';
  if (['critical', 'high', 'medium', 'low'].includes(lowerVal)) {
    level = lowerVal;
  } else if (ATTACK_SEVERITY_MAP[lowerVal]) {
    level = ATTACK_SEVERITY_MAP[lowerVal];
  } else if (severity && ['critical', 'high', 'medium', 'low'].includes(String(severity).toLowerCase())) {
    level = String(severity).toLowerCase();
  }

  // 3. Display text: show the specific prediction/attack label if available, otherwise level
  const displayText = cleanVal || level.toUpperCase();

  switch (level) {
    case 'critical':
      return (
        <span className="badge badge-critical" title={`Critical: ${displayText}`}>
          <ShieldAlert size={12} />
          {displayText}
        </span>
      );
    case 'high':
      return (
        <span className="badge badge-high" title={`High: ${displayText}`}>
          <AlertCircle size={12} />
          {displayText}
        </span>
      );
    case 'medium':
      return (
        <span className="badge badge-medium" title={`Medium: ${displayText}`}>
          <AlertTriangle size={12} />
          {displayText}
        </span>
      );
    case 'low':
    default:
      return (
        <span className="badge badge-low" title={`Low: ${displayText}`}>
          <Info size={12} />
          {displayText}
        </span>
      );
  }
};

export default SeverityBadge;

