const crypto = require('crypto');

/**
 * Request Correlation ID Middleware
 * Attaches or generates a unique correlation ID (X-Request-ID) for end-to-end tracing across microservices.
 */
const requestIdMiddleware = (req, res, next) => {
  const existingRequestId = req.headers['x-request-id'] || req.headers['x-correlation-id'];
  const requestId = existingRequestId || crypto.randomUUID();

  req.requestId = requestId;
  res.setHeader('X-Request-ID', requestId);

  next();
};

module.exports = requestIdMiddleware;
