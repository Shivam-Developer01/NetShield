const crypto = require('crypto');
const config = require('../config/env');

const { isValidServiceToken } = require('../utils/serviceAuth');

const generateCsrfToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

const csrfProtection = (req, res, next) => {
  // Read existing CSRF cookie if present
  let cookieToken = req.cookies ? req.cookies['XSRF-TOKEN'] : null;

  // Issue XSRF-TOKEN cookie on responses if missing
  if (!cookieToken) {
    cookieToken = generateCsrfToken();
    res.cookie('XSRF-TOKEN', cookieToken, {
      httpOnly: false, // Must be readable by Axios frontend client
      secure: config.nodeEnv === 'production',
      sameSite: 'lax',
      path: '/'
    });
  }

  // Safe HTTP methods do not alter state and are exempt from CSRF checks
  const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
  if (safeMethods.includes(req.method)) {
    return next();
  }

  // Service-to-Service Exemption:
  // Trusted internal machine-to-machine requests bearing a valid X-Service-Token are exempt
  // from browser Double-Submit Cookie CSRF checks because services do not rely on ambient browser cookies.
  const serviceToken = req.headers['x-service-token'];
  if (serviceToken && isValidServiceToken(serviceToken)) {
    return next();
  }

  // Public state-changing endpoints exempt from CSRF (protected by rate limit & input validation)
  const publicExemptPaths = [
    '/api/auth/login',
    '/api/auth/register',
    '/api/auth/logout',
    '/health',
    '/api/health'
  ];

  if (publicExemptPaths.includes(req.path) || publicExemptPaths.includes(req.originalUrl)) {
    return next();
  }

  // Extract CSRF token from request header
  const headerToken = req.headers['x-xsrf-token'] || req.headers['x-csrf-token'];

  // Double-submit cookie verification: Header token MUST be present and match cookie token
  if (!headerToken || !cookieToken || headerToken !== cookieToken) {
    return res.status(403).json({
      success: false,
      error: {
        code: 'CSRF_ERROR',
        message: 'Invalid or missing CSRF token. State-changing request rejected.'
      }
    });
  }

  next();
};

module.exports = {
  csrfProtection,
  generateCsrfToken
};
