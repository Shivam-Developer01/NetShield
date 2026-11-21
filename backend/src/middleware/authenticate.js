const jwt = require('jsonwebtoken');
const config = require('../config/env');
const User = require('../models/User');
const { isValidServiceToken } = require('../utils/serviceAuth');

const authenticate = async (req, res, next) => {
  try {
    // 0. Check Machine-to-Machine Service Token Header
    const serviceTokenHeader = req.headers['x-service-token'];
    if (serviceTokenHeader) {
      if (isValidServiceToken(serviceTokenHeader)) {
        req.user = {
          _id: 'service:sensor',
          id: 'service:sensor',
          username: 'sensor-service',
          email: 'sensor@netshield.internal',
          role: 'SERVICE',
          isActive: true
        };
        req.isService = true;
        return next();
      } else {
        return res.status(401).json({
          success: false,
          error: {
            code: 'INVALID_SERVICE_TOKEN',
            message: 'The provided service token is invalid.'
          }
        });
      }
    }

    let token = null;

    // 1. Check HTTP-only cookie
    if (req.cookies && req.cookies[config.cookieName]) {
      token = req.cookies[config.cookieName];
    }

    // 2. Fallback to Authorization: Bearer <token> header
    if (!token && req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHENTICATED',
          message: 'Authentication token is required. Please log in.'
        }
      });
    }

    // Verify JWT
    let decoded;
    try {
      decoded = jwt.verify(token, config.jwtSecret);
    } catch (err) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'INVALID_TOKEN',
          message: 'Authentication token is invalid or expired. Please log in again.'
        }
      });
    }

    // Find user in MongoDB
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'USER_NOT_FOUND',
          message: 'Authenticated user account no longer exists.'
        }
      });
    }

    if (!user.isActive) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'USER_INACTIVE',
          message: 'User account has been deactivated. Access denied.'
        }
      });
    }

    // Attach user to request object
    req.user = user;
    next();
  } catch (error) {
    next(error);
  }
};

module.exports = authenticate;
