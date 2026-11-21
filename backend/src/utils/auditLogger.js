const logger = require('./logger');

/**
 * Security Audit Logger
 * Logs security-relevant events with metadata while explicitly redacting credentials.
 */

const logAuditEvent = (event, metadata = {}, req = null) => {
  const ip = req ? (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || req.ip) : 'internal';
  const userAgent = req ? req.headers['user-agent'] : 'internal';

  const auditEntry = {
    timestamp: new Date().toISOString(),
    event,
    success: metadata.success !== false,
    userId: metadata.userId || (req?.user ? req.user._id : null),
    email: metadata.email || (req?.user ? req.user.email : null),
    role: metadata.role || (req?.user ? req.user.role : null),
    ip,
    userAgent,
    details: metadata.details || null
  };

  // Explicit safety check: Ensure no password, token, or secret is ever logged
  if (auditEntry.details) {
    delete auditEntry.details.password;
    delete auditEntry.details.passwordHash;
    delete auditEntry.details.token;
    delete auditEntry.details.csrfToken;
  }

  logger.info(`[AUDIT] [${event}] ${auditEntry.email || auditEntry.userId || 'anonymous'} (${ip})`, auditEntry);
  return auditEntry;
};

module.exports = {
  logAuditEvent
};
