const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const authenticate = require('../middleware/authenticate');
const { authRateLimiter } = require('../middleware/rateLimiter');
const { validateRegister, validateLogin } = require('../validators/authValidator');

// Optional authentication middleware for admin role assignment on register
const optionalAuthenticate = async (req, res, next) => {
  try {
    let token = null;
    if (req.cookies && req.cookies.netshield_token) {
      token = req.cookies.netshield_token;
    } else if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    }
    if (token) {
      const jwt = require('jsonwebtoken');
      const config = require('../config/env');
      const User = require('../models/User');
      const decoded = jwt.verify(token, config.jwtSecret);
      const user = await User.findById(decoded.id);
      if (user && user.isActive) {
        req.user = user;
      }
    }
  } catch (err) {
    // Ignore error in optional authentication
  }
  next();
};

router.get('/csrf', authController.getCsrfToken);
router.post('/register', authRateLimiter, optionalAuthenticate, validateRegister, authController.register);
router.post('/login', authRateLimiter, validateLogin, authController.login);
router.post('/logout', authController.logout);
router.get('/me', authenticate, authController.me);

module.exports = router;
