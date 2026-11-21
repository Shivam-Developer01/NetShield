/**
 * Express Application Assembly
 * Configures correlation ID tracking, security headers, CORS credentials, cookie-parser, JSON parsing, logging, CSRF protection, API routing, 404, and error handling.
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const config = require('./config/env');
const healthController = require('./controllers/healthController');
const metricsRoutes = require('./routes/metricsRoutes');
const apiRoutes = require('./routes/apiRoutes');
const requestIdMiddleware = require('./middleware/requestId');
const { csrfProtection } = require('./middleware/csrfProtection');
const authenticate = require('./middleware/authenticate');
const authorize = require('./middleware/authorize');
const notFound = require('./middleware/notFound');
const errorHandler = require('./middleware/errorHandler');
const metricsCollector = require('./utils/metricsCollector');

const app = express();

// 1. Request Correlation ID Middleware (Mount FIRST to trace all incoming requests)
app.use(requestIdMiddleware);

// 1b. HTTP Metrics Tracker Middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    metricsCollector.recordHttpRequest(req.method, res.statusCode, duration);
  });
  next();
});

// 2. Enhanced Security Headers (Helmet)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'", "http://localhost:5000", "http://127.0.0.1:5000", "http://localhost:5173", "http://127.0.0.1:8000"]
    }
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  frameguard: { action: 'deny' },
  xContentTypeOptions: true
}));

// 3. Cookie Parser
app.use(cookieParser());

// 4. CORS Middleware
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (config.corsOrigins.includes(origin) || config.corsOrigins.includes('*')) {
      return callback(null, true);
    }
    return callback(new Error(`CORS Policy Violation: Origin '${origin}' is not allowed.`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-XSRF-TOKEN', 'X-CSRF-TOKEN', 'X-Request-ID', 'X-Service-Token']
}));

// 5. Body Parsing Middleware
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// 6. Public Health, Readiness & Liveness Endpoints
app.get('/health', healthController.getHealthStatus);
app.get('/live', healthController.getLiveness);
app.get('/ready', healthController.getReadiness);

// 7. Prometheus & JSON Operational Metrics Endpoints
app.use('/metrics', metricsRoutes);

// 8. CSRF Protection Middleware
app.use('/api', csrfProtection);

// 8b. Sensor Telemetry Endpoint (Internal sensor reporting)
app.post(
  '/api/sensor/telemetry',
  authenticate,
  authorize('ADMIN', 'ANALYST', 'SERVICE'),
  (req, res) => {
    metricsCollector.updateSensorTelemetry(req.body);
    res.status(200).json({ success: true });
  }
);

// 9. API Sub-Routes
app.use('/api', apiRoutes);

// 9. Catch 404 Route Not Found
app.use(notFound);

// 10. Centralized Error Handler
app.use(errorHandler);

module.exports = app;
