const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const app = require('../src/app');
const config = require('../src/config/env');
const { isValidServiceToken } = require('../src/utils/serviceAuth');
const mlService = require('../src/services/mlService');

jest.mock('../src/services/mlService');

describe('Phase 20.11: Service-to-Service Authentication & CSRF Protection Suite', () => {
  const validServiceToken = config.sensorServiceToken;
  let mongoServer;

  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create();
    await mongoose.connect(mongoServer.getUri());
  }, 20000);

  afterAll(async () => {
    await mongoose.disconnect();
    await mongoServer.stop();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('1. isValidServiceToken Utility', () => {
    it('returns true for exact matching service token', () => {
      expect(isValidServiceToken(validServiceToken)).toBe(true);
    });

    it('returns false for invalid or tampered service token', () => {
      expect(isValidServiceToken('invalid_token_12345')).toBe(false);
      expect(isValidServiceToken(validServiceToken + '_tampered')).toBe(false);
      expect(isValidServiceToken('')).toBe(false);
      expect(isValidServiceToken(null)).toBe(false);
      expect(isValidServiceToken(undefined)).toBe(false);
      expect(isValidServiceToken(12345)).toBe(false);
    });
  });

  describe('2. POST /api/sensor/telemetry Endpoint', () => {
    it('accepts telemetry with valid X-Service-Token header without requiring CSRF token', async () => {
      const telemetryPayload = {
        packetsProcessed: 10,
        flowsCreated: 3,
        activeFlows: 0,
        validationFailures: 0,
        predictionsSent: 3,
        errors: 0,
        status: 'healthy'
      };

      const res = await request(app)
        .post('/api/sensor/telemetry')
        .set('X-Service-Token', validServiceToken)
        .send(telemetryPayload);

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('rejects telemetry without X-Service-Token or CSRF cookie (403 or 401)', async () => {
      const res = await request(app)
        .post('/api/sensor/telemetry')
        .send({ packetsProcessed: 10 });

      expect([401, 403]).toContain(res.statusCode);
      expect(res.body.success).toBe(false);
    });

    it('rejects telemetry with an invalid X-Service-Token', async () => {
      const res = await request(app)
        .post('/api/sensor/telemetry')
        .set('X-Service-Token', 'malicious_wrong_token')
        .send({ packetsProcessed: 10 });

      expect([401, 403]).toContain(res.statusCode);
      expect(res.body.success).toBe(false);
    });
  });

  describe('3. POST /api/predictions Service Authorization', () => {
    it('allows SERVICE role with valid X-Service-Token to submit predictions without CSRF cookie', async () => {
      mlService.predict.mockResolvedValueOnce({
        dataset_type: 'nsl_kdd',
        model_version: 'NetShield-NSLKDD-XGBoost-v1.0',
        records_processed: 1,
        client_latency_ms: 12.5,
        predictions: [
          {
            prediction: 'Normal',
            confidence: 0.985,
            prediction_index: 0,
            class_probabilities: { Normal: 0.985, Attack: 0.015 }
          }
        ]
      });

      const predictionPayload = {
        datasetType: 'nsl_kdd',
        inputData: {
          duration: 0,
          protocol_type: 'tcp',
          service: 'http',
          flag: 'SF',
          src_bytes: 181,
          dst_bytes: 5450
        }
      };

      const res = await request(app)
        .post('/api/predictions')
        .set('X-Service-Token', validServiceToken)
        .send(predictionPayload);

      // Should not be rejected by CSRF or 401/403
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
      expect([200, 201]).toContain(res.statusCode);
      expect(res.body.success).toBe(true);
    });

    it('rejects POST /api/predictions without service token or CSRF token with HTTP 403 CSRF_ERROR', async () => {
      const res = await request(app)
        .post('/api/predictions')
        .send({ datasetType: 'nsl_kdd', inputData: {} });

      expect(res.statusCode).toBe(403);
      expect(res.body.error.code).toBe('CSRF_ERROR');
    });
  });

  describe('4. Privilege Escalation Prevention', () => {
    it('denies SERVICE role access to ADMIN user management routes (/api/users)', async () => {
      const res = await request(app)
        .get('/api/users')
        .set('X-Service-Token', validServiceToken);

      expect(res.statusCode).toBe(403);
      expect(res.body.error.code).toBe('FORBIDDEN');
    });
  });

  describe('5. Browser CSRF Protection Integrity', () => {
    it('still rejects state-changing requests when CSRF cookie is present but header is missing or mismatched', async () => {
      const res = await request(app)
        .post('/api/auth/register') // Wait, register is in publicExemptPaths
        .send({});
      // Test an endpoint subject to CSRF without service token
      const resProtected = await request(app)
        .post('/api/predictions')
        .set('Cookie', ['netshield_token=some_user_token; XSRF-TOKEN=secret_cookie_token'])
        .set('X-XSRF-TOKEN', 'wrong_mismatched_token')
        .send({ datasetType: 'nsl_kdd', inputData: {} });

      expect(resProtected.statusCode).toBe(403);
      expect(resProtected.body.error.code).toBe('CSRF_ERROR');
    });
  });
});
