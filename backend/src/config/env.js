const path = require('path');
const dotenv = require('dotenv');

// Load environment variables from .env file if available
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const nodeEnv = process.env.NODE_ENV || 'development';
const isProd = nodeEnv === 'production';

// Production Validation Safeguard: Fail fast if insecure default keys are used in production
if (isProd) {
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.includes('phase11_dev')) {
    throw new Error('[FATAL PRODUCTION CONFIG ERROR] Insecure or default JWT_SECRET detected in production environment!');
  }
  if (!process.env.MONGODB_URI) {
    throw new Error('[FATAL PRODUCTION CONFIG ERROR] MONGODB_URI must be explicitly specified in production!');
  }
}

const config = {
  port: parseInt(process.env.PORT || '5000', 10),
  nodeEnv,
  isTest: nodeEnv === 'test',
  isProd,
  logLevel: process.env.LOG_LEVEL || (isProd ? 'info' : 'debug'),
  mongodbUri: process.env.MONGODB_URI || 'mongodb://localhost:27017/netshield_db',
  mlServiceUrl: process.env.ML_SERVICE_URL || 'http://127.0.0.1:8000',
  mlServiceTimeoutMs: parseInt(process.env.ML_SERVICE_TIMEOUT_MS || '10000', 10),
  corsOrigins: (process.env.CORS_ORIGINS || 'http://localhost:5173,http://127.0.0.1:5173')
    .split(',')
    .map(origin => origin.trim()),
  jwtSecret: process.env.JWT_SECRET || 'netshield_super_secret_jwt_key_phase11_dev_2026',
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '1h',
  cookieName: process.env.COOKIE_NAME || 'netshield_token',
  cookieSecure: process.env.COOKIE_SECURE ? process.env.COOKIE_SECURE === 'true' : isProd,
  cookieSameSite: process.env.COOKIE_SAME_SITE || 'lax',
  sensorServiceToken: process.env.SENSOR_SERVICE_TOKEN || 'netshield_sensor_internal_service_token_phase20_11_secure',
  authRateLimitWindowMs: parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 mins
  authRateLimitMax: parseInt(process.env.AUTH_RATE_LIMIT_MAX || '10', 10),
  adminEmail: process.env.ADMIN_EMAIL || 'admin@netshield.local',
  adminPassword: process.env.ADMIN_PASSWORD || 'AdminSecurePassword123!',
  adminUsername: process.env.ADMIN_USERNAME || 'sysadmin',
  smtp: {
    host: process.env.SMTP_HOST || '',
    port: parseInt(process.env.SMTP_PORT || '587', 10),
    secure: process.env.SMTP_SECURE === 'true',
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || '',
    from: process.env.SMTP_FROM || process.env.SMTP_USER || 'no-reply@netshield.local',
    get isConfigured() {
      return Boolean(this.host && this.user && this.pass);
    }
  }
};

module.exports = config;
