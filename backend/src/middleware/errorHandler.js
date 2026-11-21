/**
 * Centralized Express Error Handling Middleware
 * Suppresses internal stack traces in production while returning safe, structured HTTP error responses.
 */

const config = require('../config/env');
const logger = require('../utils/logger');

const errorHandler = (err, req, res, next) => {
  let statusCode = err.statusCode || (res.statusCode !== 200 ? res.statusCode : 500);
  let message = err.message || 'An unexpected internal server error occurred.';

  // Handle Mongoose CastError (e.g. malformed ObjectId parameters)
  if (err.name === 'CastError' || err.kind === 'ObjectId') {
    statusCode = 400;
    message = `Invalid ID format for parameter '${err.path || 'id'}'`;
  }

  logger.error(message, {
    requestId: req.requestId || null,
    url: req.originalUrl,
    method: req.method,
    statusCode,
    details: err.details || null
  });

  const response = {
    success: false,
    error: {
      message,
      status: statusCode,
      requestId: req.requestId || null
    }
  };

  if (err.details) {
    response.error.details = err.details;
  }

  // Include stack trace ONLY in development (NEVER in production or test)
  if (config.nodeEnv === 'development') {
    response.error.stack = err.stack;
  }

  res.status(statusCode).json(response);
};

module.exports = errorHandler;
