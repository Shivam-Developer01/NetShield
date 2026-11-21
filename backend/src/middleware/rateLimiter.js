const rateLimit = require('express-rate-limit');
const config = require('../config/env');

const authRateLimiter = rateLimit({
  windowMs: config.authRateLimitWindowMs, // Default: 15 mins
  max: config.authRateLimitMax, // Default: 10 attempts
  standardHeaders: true,
  legacyHeaders: false,
  skip: () => config.isTest, // Disable in test environment to avoid test interference
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      error: {
        code: 'TOO_MANY_REQUESTS',
        message: 'Too many authentication attempts. Please try again later.'
      }
    });
  }
});

module.exports = {
  authRateLimiter
};
