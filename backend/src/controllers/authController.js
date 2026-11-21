const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('../config/env');
const User = require('../models/User');
const { logAuditEvent } = require('../utils/auditLogger');
const { generateCsrfToken } = require('../middleware/csrfProtection');

const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, role: user.role },
    config.jwtSecret,
    { expiresIn: config.jwtExpiresIn }
  );
};

const sendTokenResponse = (user, statusCode, res, req) => {
  const token = generateToken(user);

  const cookieOptions = {
    httpOnly: true,
    secure: config.nodeEnv === 'production',
    sameSite: 'lax',
    maxAge: 3600000 // 1 hour in ms
  };

  res.cookie(config.cookieName, token, cookieOptions);

  // Issue CSRF token cookie for non-GET requests
  const csrfToken = generateCsrfToken();
  res.cookie('XSRF-TOKEN', csrfToken, {
    httpOnly: false,
    secure: config.nodeEnv === 'production',
    sameSite: 'lax',
    path: '/'
  });

  logAuditEvent('LOGIN_SUCCESS', { userId: user._id, email: user.email, role: user.role }, req);

  return res.status(statusCode).json({
    success: true,
    token,
    csrfToken,
    user: {
      id: user._id,
      username: user.username,
      email: user.email,
      role: user.role,
      isActive: user.isActive,
      lastLoginAt: user.lastLoginAt
    }
  });
};

const register = async (req, res, next) => {
  try {
    const { username, email, password, role } = req.body;

    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      logAuditEvent('REGISTER_FAILURE', { email, details: { reason: 'Duplicate email' }, success: false }, req);
      return res.status(409).json({
        success: false,
        error: {
          code: 'DUPLICATE_EMAIL',
          message: 'An account with this email address already exists.'
        }
      });
    }

    let assignedRole = 'VIEWER';
    if (req.user && req.user.role === 'ADMIN' && role) {
      assignedRole = role;
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const newUser = await User.create({
      username,
      email: email.toLowerCase(),
      passwordHash,
      role: assignedRole,
      isActive: true
    });

    logAuditEvent('REGISTER', { userId: newUser._id, email: newUser.email, role: assignedRole }, req);

    const userObj = newUser.toObject();
    delete userObj.passwordHash;

    return res.status(201).json({
      success: true,
      message: 'User account created successfully.',
      user: userObj
    });
  } catch (error) {
    next(error);
  }
};

const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email: email.toLowerCase() }).select('+passwordHash');
    if (!user) {
      logAuditEvent('LOGIN_FAILURE', { email, details: { reason: 'User not found' }, success: false }, req);
      return res.status(401).json({
        success: false,
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password.'
        }
      });
    }

    if (!user.isActive) {
      logAuditEvent('LOGIN_FAILURE', { email, details: { reason: 'Account inactive' }, success: false }, req);
      return res.status(401).json({
        success: false,
        error: {
          code: 'USER_INACTIVE',
          message: 'Invalid email or password.'
        }
      });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      logAuditEvent('LOGIN_FAILURE', { email, details: { reason: 'Incorrect password' }, success: false }, req);
      return res.status(401).json({
        success: false,
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password.'
        }
      });
    }

    user.lastLoginAt = new Date();
    await user.save();

    return sendTokenResponse(user, 200, res, req);
  } catch (error) {
    next(error);
  }
};

const logout = async (req, res) => {
  logAuditEvent('LOGOUT', { userId: req.user?._id, email: req.user?.email }, req);

  res.clearCookie(config.cookieName, {
    httpOnly: true,
    secure: config.nodeEnv === 'production',
    sameSite: 'lax'
  });

  return res.status(200).json({
    success: true,
    message: 'Logged out successfully.'
  });
};

const me = async (req, res) => {
  return res.status(200).json({
    success: true,
    user: {
      id: req.user._id,
      username: req.user.username,
      email: req.user.email,
      role: req.user.role,
      isActive: req.user.isActive,
      lastLoginAt: req.user.lastLoginAt
    }
  });
};

const getCsrfToken = async (req, res) => {
  let csrfToken = req.cookies['XSRF-TOKEN'];
  if (!csrfToken) {
    csrfToken = generateCsrfToken();
    res.cookie('XSRF-TOKEN', csrfToken, {
      httpOnly: false,
      secure: config.nodeEnv === 'production',
      sameSite: 'lax',
      path: '/'
    });
  }
  return res.status(200).json({
    success: true,
    csrfToken
  });
};

module.exports = {
  register,
  login,
  logout,
  me,
  getCsrfToken
};
