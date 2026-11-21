/**
 * NetShield Backend Logger Utility
 * Provides structured logging with request correlation IDs while sanitizing sensitive credentials and raw payloads.
 */

const config = require('../config/env');

const levels = {
  error: 0,
  warn: 1,
  info: 2,
  debug: 3
};

const currentLevel = () => {
  return levels[config.logLevel] !== undefined ? levels[config.logLevel] : levels.info;
};

const formatMessage = (level, message, meta = {}) => {
  const timestamp = new Date().toISOString();
  
  // Sanitize any potential secret keys
  const sanitizedMeta = { ...meta };
  delete sanitizedMeta.password;
  delete sanitizedMeta.passwordHash;
  delete sanitizedMeta.secret;
  delete sanitizedMeta.token;
  delete sanitizedMeta.jwt;
  delete sanitizedMeta.jwtSecret;
  delete sanitizedMeta.authorization;
  delete sanitizedMeta.csrfToken;
  delete sanitizedMeta.cookie;
  delete sanitizedMeta.apiKey;
  delete sanitizedMeta.serviceToken;
  delete sanitizedMeta.sensorServiceToken;
  delete sanitizedMeta.xServiceToken;
  delete sanitizedMeta.mongoUri;
  delete sanitizedMeta.mongodbUri;

  const logObj = {
    timestamp,
    level: level.toUpperCase(),
    service: 'netshield-backend',
    message,
    ...sanitizedMeta
  };

  return JSON.stringify(logObj);
};

const logger = {
  info: (msg, meta) => {
    if (currentLevel() >= levels.info && !config.isTest) {
      console.log(formatMessage('info', msg, meta));
    }
  },
  warn: (msg, meta) => {
    if (currentLevel() >= levels.warn && !config.isTest) {
      console.warn(formatMessage('warn', msg, meta));
    }
  },
  error: (msg, meta) => {
    if (currentLevel() >= levels.error && !config.isTest) {
      console.error(formatMessage('error', msg, meta));
    }
  },
  debug: (msg, meta) => {
    if (currentLevel() >= levels.debug && !config.isTest) {
      console.log(formatMessage('debug', msg, meta));
    }
  }
};

module.exports = logger;
