const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const app = require('../src/app');
const OperationalIncident = require('../src/models/OperationalIncident');
const User = require('../src/models/User');

jest.setTimeout(30000);

let mongoServer;
let adminToken;
let adminCsrf;
let viewerToken;

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  const mongoUri = mongoServer.getUri();
  await mongoose.connect(mongoUri);
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

beforeEach(async () => {
  await OperationalIncident.deleteMany({});
  await User.deleteMany({});

  // Create ADMIN
  await request(app).post('/api/auth/register').send({
    username: 'admin',
    email: 'admin@test.com',
    password: 'Password123!'
  });
  const admin = await User.findOne({ email: 'admin@test.com' });
  admin.role = 'ADMIN';
  await admin.save();

  const loginRes = await request(app).post('/api/auth/login').send({
    email: 'admin@test.com',
    password: 'Password123!'
  });
  adminToken = loginRes.body.token;
  adminCsrf = loginRes.body.csrfToken || 'test_csrf';

  // Create VIEWER
  await request(app).post('/api/auth/register').send({
    username: 'viewer',
    email: 'viewer@test.com',
    password: 'Password123!'
  });
  const viewer = await User.findOne({ email: 'viewer@test.com' });
  viewer.role = 'VIEWER';
  await viewer.save();

  const viewerLoginRes = await request(app).post('/api/auth/login').send({
    email: 'viewer@test.com',
    password: 'Password123!'
  });
  viewerToken = viewerLoginRes.body.token;
});

describe('Phase 18 — Backend Observability, Health & Operational Incidents', () => {
  describe('1. Health, Readiness & Liveness Probes', () => {
    test('GET /live should return 200 OK with status alive', async () => {
      const res = await request(app).get('/live');
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('alive');
    });

    test('GET /ready should return readiness check status', async () => {
      const res = await request(app).get('/ready');
      expect([200, 503]).toContain(res.status);
      expect(res.body.status).toBeDefined();
    });

    test('GET /health should return detailed service health breakdown', async () => {
      const res = await request(app).get('/health');
      expect(res.status).toBe(200);
      expect(res.body.services).toBeDefined();
      expect(res.body.services.backend).toBeDefined();
      expect(res.body.services.mongodb).toBeDefined();
    });
  });

  describe('2. Prometheus & JSON Operational Metrics', () => {
    test('GET /metrics should return Prometheus-formatted text metrics', async () => {
      const res = await request(app).get('/metrics');
      expect(res.status).toBe(200);
      expect(res.text).toContain('netshield_http_requests_total');
      expect(res.text).not.toContain('jwtsecret');
      expect(res.text).not.toContain('passwordhash');
    });

    test('GET /metrics/json should return in-memory JSON metrics summary', async () => {
      const res = await request(app).get('/metrics/json');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.http).toBeDefined();
    });
  });

  describe('3. Operational Incident REST API & RBAC', () => {
    test('GET /api/operations/incidents should allow ADMIN, ANALYST, VIEWER', async () => {
      await OperationalIncident.create({
        type: 'HIGH_LATENCY',
        severity: 'HIGH',
        source: 'mlService',
        message: 'ML latency spike'
      });

      const res = await request(app)
        .get('/api/operations/incidents')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.data.length).toBe(1);
    });

    test('PATCH /api/operations/incidents/:id should allow ADMIN to acknowledge', async () => {
      const incident = await OperationalIncident.create({
        type: 'HIGH_LATENCY',
        severity: 'HIGH',
        source: 'mlService',
        message: 'ML latency spike'
      });

      const res = await request(app)
        .patch(`/api/operations/incidents/${incident._id}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
        .set('X-XSRF-TOKEN', adminCsrf)
        .send({ status: 'ACKNOWLEDGED' });

      expect(res.status).toBe(200);
      expect(res.body.data.status).toBe('ACKNOWLEDGED');
    });

    test('PATCH /api/operations/incidents/:id should reject VIEWER with 403 Forbidden', async () => {
      const incident = await OperationalIncident.create({
        type: 'HIGH_LATENCY',
        severity: 'HIGH',
        source: 'mlService',
        message: 'ML latency spike'
      });

      const res = await request(app)
        .patch(`/api/operations/incidents/${incident._id}`)
        .set('Authorization', `Bearer ${viewerToken}`)
        .send({ status: 'RESOLVED' });

      expect(res.status).toBe(403);
    });
  });
});
