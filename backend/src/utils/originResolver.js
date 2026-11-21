/**
 * NetShield Canonical Network Origin Resolver & Formatter
 * 
 * Provides unified resolution, validation, sanitization, and formatting
 * of network-flow metadata across all alert generation paths (Sensor, Manual Predict, API).
 *
 * Guaranteed Constraints:
 * 1. Never fabricates missing IPs, ports, protocols, or flow IDs.
 * 2. Does NOT treat arbitrary tabular ML dataset features (e.g. protocol_type or Destination Port)
 *    as authentic network origin unless authentic flow/source metadata exists.
 * 3. Validates IP strings (IPv4/IPv6), port bounds (0-65535 integer), and protocol strings.
 * 4. Consistently formats partial vs full metadata according to Phase 20.13.1 specifications:
 *    - Full TCP/UDP: src:srcPort -> dst:dstPort [PROTO]
 *    - IP-only: src -> dst [PROTO]
 *    - Protocol + no IP: unknown -> unknown [PROTO]
 *    - Port + no IP: unknown:N/A -> unknown:dstPort [PROTO]  (or with known protocol)
 *    - ICMP: src -> dst [ICMP] (never fake ports)
 *    - Missing: unknown:N/A -> unknown:N/A [N/A]
 */

const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const IPV6_REGEX = /^[0-9a-fA-F:]+$/;

const isValidIp = (val) => {
  if (typeof val !== 'string') return false;
  const trimmed = val.trim();
  if (trimmed === 'unknown' || trimmed === 'N/A' || trimmed === '') return false;
  return IPV4_REGEX.test(trimmed) || (IPV6_REGEX.test(trimmed) && trimmed.includes(':'));
};

const isValidPort = (val) => {
  if (val === undefined || val === null || val === '' || val === 'N/A') return false;
  const num = Number(val);
  return Number.isInteger(num) && num >= 0 && num <= 65535;
};

const sanitizePort = (val) => {
  if (!isValidPort(val)) return undefined;
  return Number(val);
};

const sanitizeProtocol = (val) => {
  if (!val || typeof val !== 'string') return null;
  const clean = val.trim().toUpperCase();
  if (!clean || clean === 'UNKNOWN' || clean === 'N/A') return null;
  return clean.replace(/[^A-Z0-9_\-]/g, '');
};

const escapeHtml = (str) => String(str || '').replace(/[&<>"']/g, (m) => ({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;'
}[m]));

/**
 * Resolves authoritative network source info from sourceInfo and inputData.
 * Prioritizes explicit trusted sourceInfo (e.g. from sensor or authenticated API).
 *
 * @param {Object|null} sourceInfo
 * @param {Object|null} inputData
 * @returns {Object|null}
 */
const resolveNetworkSourceInfo = (sourceInfo, inputData) => {
  const sInfo = (sourceInfo && typeof sourceInfo === 'object') ? { ...sourceInfo } : {};
  const iData = (inputData && typeof inputData === 'object') ? inputData : {};

  // 1. Resolve IPs (explicit sourceInfo first, then explicit inputData network fields)
  const rawSrcIp = sInfo.src_ip || sInfo['Source IP'] || iData.src_ip || iData['Source IP'] || null;
  const rawDstIp = sInfo.dst_ip || sInfo['Destination IP'] || iData.dst_ip || iData['Destination IP'] || null;

  const validSrcIp = isValidIp(rawSrcIp) ? rawSrcIp.trim() : null;
  const validDstIp = isValidIp(rawDstIp) ? rawDstIp.trim() : null;

  // 2. Resolve Ports (explicit sourceInfo first)
  const rawSrcPort = sInfo.src_port !== undefined ? sInfo.src_port : (sInfo['Source Port'] !== undefined ? sInfo['Source Port'] : iData.src_port);
  const rawDstPort = sInfo.dst_port !== undefined ? sInfo.dst_port : (sInfo['Destination Port'] !== undefined ? sInfo['Destination Port'] : iData.dst_port);

  const validSrcPort = sanitizePort(rawSrcPort);
  const validDstPort = sanitizePort(rawDstPort);

  // 3. Resolve Protocol
  const rawProtocol = sInfo.protocol || sInfo['Protocol'] || iData.protocol || iData['Protocol'] || null;
  const validProtocol = sanitizeProtocol(rawProtocol);

  // 4. Resolve Flow ID
  const rawFlowId = sInfo.flow_id || sInfo.flowId || iData.flow_id || iData.flowId || null;
  const validFlowId = (rawFlowId && typeof rawFlowId === 'string' && rawFlowId.trim() !== '') ? rawFlowId.trim() : null;

  // Check if any genuine network origin coordinate exists
  const hasOriginData = Boolean(
    validSrcIp || validDstIp ||
    validSrcPort !== undefined || validDstPort !== undefined ||
    validProtocol || validFlowId
  );

  if (!hasOriginData) {
    // If sourceInfo has other non-network metadata (like groundTruth, sensor name), preserve them
    return Object.keys(sInfo).length > 0 ? sInfo : null;
  }

  // Populate canonical fields into enriched object
  if (validSrcIp) sInfo.src_ip = validSrcIp;
  if (validDstIp) sInfo.dst_ip = validDstIp;
  if (validSrcPort !== undefined) sInfo.src_port = validSrcPort;
  if (validDstPort !== undefined) sInfo.dst_port = validDstPort;
  if (validProtocol) sInfo.protocol = validProtocol;
  if (validFlowId) sInfo.flow_id = validFlowId;

  return sInfo;
};

/**
 * Formats the network origin description according to Phase 20.13.1 rules:
 * - FULL TCP/UDP: src:srcPort -> dst:dstPort [PROTO]
 * - IP-only: src -> dst [PROTO]
 * - Protocol + no IP: unknown -> unknown [PROTO]
 * - Port + no IP: unknown:N/A -> unknown:dstPort [PROTO]
 * - ICMP: src -> dst [ICMP] (no ports)
 * - Completely missing: unknown:N/A -> unknown:N/A [N/A]
 *
 * @param {Object|null} sourceInfo
 * @param {boolean} isHtml
 * @returns {string}
 */
const formatNetworkOrigin = (sourceInfo, isHtml = false) => {
  const sInfo = sourceInfo || {};
  const rawSrcIp = sInfo.src_ip || sInfo['Source IP'];
  const rawDstIp = sInfo.dst_ip || sInfo['Destination IP'];
  const rawSrcPort = sInfo.src_port !== undefined ? sInfo.src_port : sInfo['Source Port'];
  const rawDstPort = sInfo.dst_port !== undefined ? sInfo.dst_port : sInfo['Destination Port'];
  const rawProtocol = sInfo.protocol || sInfo['Protocol'] || sInfo.protocol_type;

  const srcIpRaw = rawSrcIp !== undefined && rawSrcIp !== null ? String(rawSrcIp) : null;
  const dstIpRaw = rawDstIp !== undefined && rawDstIp !== null ? String(rawDstIp) : null;
  const hasSrcIp = Boolean(srcIpRaw && srcIpRaw.trim() !== '' && srcIpRaw.trim() !== 'unknown');
  const hasDstIp = Boolean(dstIpRaw && dstIpRaw.trim() !== '' && dstIpRaw.trim() !== 'unknown');

  const validSrcPort = sanitizePort(rawSrcPort);
  const validDstPort = sanitizePort(rawDstPort);
  const protoUpper = rawProtocol ? String(rawProtocol).toUpperCase() : 'N/A';

  const hasAnyMetadata = Boolean(
    hasSrcIp || hasDstIp ||
    (rawSrcPort !== undefined && rawSrcPort !== null && rawSrcPort !== '' && rawSrcPort !== 'N/A') ||
    (rawDstPort !== undefined && rawDstPort !== null && rawDstPort !== '' && rawDstPort !== 'N/A') ||
    (rawProtocol && String(rawProtocol).trim() !== '' && String(rawProtocol).trim() !== 'N/A')
  );

  const arrow = isHtml ? ' &rarr; ' : ' -> ';

  if (!hasAnyMetadata) {
    return `unknown:N/A${arrow}unknown:N/A [N/A]`;
  }

  const isPortless = ['ICMP', 'IGMP', 'GRE', 'ESP', 'AH'].includes(protoUpper);

  const hasSrcP = !isPortless && validSrcPort !== undefined;
  const hasDstP = !isPortless && validDstPort !== undefined;
  const hasAnyPort = hasSrcP || hasDstP;

  const esc = (val) => (isHtml ? escapeHtml(val) : String(val));

  let srcStr = '';
  let dstStr = '';

  if (isPortless) {
    // Portless protocols like ICMP never show ports
    srcStr = hasSrcIp ? esc(srcIpRaw) : 'unknown';
    dstStr = hasDstIp ? esc(dstIpRaw) : 'unknown';
  } else if (!hasSrcIp && !hasDstIp) {
    // Both IPs missing
    if (hasAnyPort) {
      // Port + no IP rule: unknown:srcPort or unknown:N/A -> unknown:dstPort
      const sp = hasSrcP ? esc(String(validSrcPort)) : 'N/A';
      const dp = hasDstP ? esc(String(validDstPort)) : 'N/A';
      srcStr = `unknown:${sp}`;
      dstStr = `unknown:${dp}`;
    } else {
      // Protocol + no IP rule: unknown -> unknown [PROTO]
      srcStr = 'unknown';
      dstStr = 'unknown';
    }
  } else if (hasSrcIp && hasDstIp) {
    // Both IPs available
    if (hasSrcP && hasDstP) {
      srcStr = `${esc(srcIpRaw)}:${esc(String(validSrcPort))}`;
      dstStr = `${esc(dstIpRaw)}:${esc(String(validDstPort))}`;
    } else if (hasSrcP && !hasDstP) {
      srcStr = `${esc(srcIpRaw)}:${esc(String(validSrcPort))}`;
      dstStr = esc(dstIpRaw);
    } else if (!hasSrcP && hasDstP) {
      srcStr = esc(srcIpRaw);
      dstStr = `${esc(dstIpRaw)}:${esc(String(validDstPort))}`;
    } else {
      // IP-only rule: src -> dst [PROTO]
      srcStr = esc(srcIpRaw);
      dstStr = esc(dstIpRaw);
    }
  } else {
    // Exactly one IP available
    if (hasSrcIp) {
      srcStr = hasSrcP ? `${esc(srcIpRaw)}:${esc(String(validSrcPort))}` : esc(srcIpRaw);
      dstStr = hasDstP ? `unknown:${esc(String(validDstPort))}` : 'unknown';
    } else {
      srcStr = hasSrcP ? `unknown:${esc(String(validSrcPort))}` : 'unknown';
      dstStr = hasDstP ? `${esc(dstIpRaw)}:${esc(String(validDstPort))}` : esc(dstIpRaw);
    }
  }

  const protoDisplay = esc(protoUpper);
  return `${srcStr}${arrow}${dstStr} [${protoDisplay}]`;
};

module.exports = {
  isValidIp,
  isValidPort,
  sanitizePort,
  sanitizeProtocol,
  resolveNetworkSourceInfo,
  formatNetworkOrigin
};
