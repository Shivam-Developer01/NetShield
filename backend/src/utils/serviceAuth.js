const crypto = require('crypto');
const config = require('../config/env');

/**
 * Validates a machine-to-machine service token using constant-time comparison
 * to prevent timing attacks.
 * 
 * @param {string} providedToken - The token provided in request header (e.g., X-Service-Token)
 * @returns {boolean} True if token matches configured sensorServiceToken
 */
const isValidServiceToken = (providedToken) => {
  if (!providedToken || typeof providedToken !== 'string') {
    return false;
  }
  const configuredToken = config.sensorServiceToken;
  if (!configuredToken || typeof configuredToken !== 'string' || configuredToken.length === 0) {
    return false;
  }
  const bufA = Buffer.from(providedToken, 'utf8');
  const bufB = Buffer.from(configuredToken, 'utf8');
  if (bufA.length !== bufB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
};

module.exports = {
  isValidServiceToken
};
