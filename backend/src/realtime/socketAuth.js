const jwt = require('jsonwebtoken');
const config = require('../config/env');
const User = require('../models/User');
const { logAuditEvent } = require('../utils/auditLogger');
const logger = require('../utils/logger');

/**
 * Parses raw Cookie header string into key-value pairs
 */
function parseCookies(cookieHeader) {
  const list = {};
  if (!cookieHeader) return list;
  cookieHeader.split(';').forEach((cookie) => {
    let [name, ...rest] = cookie.split('=');
    name = name?.trim();
    if (!name) return;
    const value = rest.join('=').trim();
    if (!value) return;
    list[name] = decodeURIComponent(value);
  });
  return list;
}

/**
 * Socket.IO Handshake Authentication Middleware
 * Reuses existing HTTP-only JWT Cookie authentication & active user check
 */
const socketAuth = async (socket, next) => {
  try {
    const rawCookies = socket.handshake.headers.cookie;
    const cookies = parseCookies(rawCookies);
    let token = cookies[config.cookieName || 'netshield_token'];

    // Fallback: check handshake auth object for testing environments
    if (!token && socket.handshake.auth && socket.handshake.auth.token) {
      token = socket.handshake.auth.token;
    }

    if (!token) {
      logAuditEvent('SOCKET_AUTH_FAILED', {
        success: false,
        details: { reason: 'No authentication token provided in socket handshake' }
      });
      return next(new Error('Authentication error: Token required'));
    }

    let decoded;
    try {
      decoded = jwt.verify(token, config.jwtSecret);
    } catch (err) {
      logAuditEvent('SOCKET_AUTH_FAILED', {
        success: false,
        details: { reason: 'Invalid or expired token', error: err.message }
      });
      return next(new Error('Authentication error: Invalid or expired token'));
    }

    const user = await User.findById(decoded.id).select('-password');
    if (!user) {
      logAuditEvent('SOCKET_AUTH_FAILED', {
        success: false,
        details: { reason: 'User not found' }
      });
      return next(new Error('Authentication error: User not found'));
    }

    if (!user.isActive) {
      logAuditEvent('SOCKET_AUTH_FAILED', {
        success: false,
        userId: user._id,
        email: user.email,
        details: { reason: 'User account disabled' }
      });
      return next(new Error('Authentication error: User account disabled'));
    }

    socket.user = {
      _id: user._id.toString(),
      id: user._id.toString(),
      email: user.email,
      role: user.role,
      name: user.name,
    };

    return next();
  } catch (error) {
    logger.error(`[SocketAuth] Unexpected error during socket authentication: ${error.message}`);
    return next(new Error('Authentication error: Internal error'));
  }
};

module.exports = socketAuth;
