const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const app = require('../src/app');
const Alert = require('../src/models/Alert');
const User = require('../src/models/User');

let mongoServer;
let adminToken;
let adminCsrf;

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
  await Alert.deleteMany({});
  await User.deleteMany({});

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
});

describe('Alerts API Endpoints', () => {
  test('GET /api/alerts returns paginated alert list with status filtering', async () => {
    await Alert.create([
      { severity: 'high', attackType: 'DoS', prediction: 'DoS', confidence: 0.99, datasetType: 'nsl_kdd', modelVersion: 'v1', status: 'open', description: 'DoS attack' },
      { severity: 'medium', attackType: 'PortScan', prediction: 'PortScan', confidence: 0.95, datasetType: 'cicids2017', modelVersion: 'v1', status: 'resolved', description: 'Port scan' }
    ]);

    const res = await request(app)
      .get('/api/alerts?status=open')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.statusCode).toEqual(200);
    expect(res.body.pagination.total).toEqual(1);
    expect(res.body.data[0].attackType).toEqual('DoS');
    expect(res.body.data[0].status).toEqual('open');
  });

  test('GET /api/alerts/:id returns single alert details', async () => {
    const alert = await Alert.create({
      severity: 'critical', attackType: 'U2R', prediction: 'U2R', confidence: 0.98, datasetType: 'nsl_kdd', modelVersion: 'v1', status: 'open', description: 'Privilege escalation'
    });

    const res = await request(app)
      .get(`/api/alerts/${alert._id}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.statusCode).toEqual(200);
    expect(res.body.data.attackType).toEqual('U2R');
    expect(res.body.data.severity).toEqual('critical');
  });

  test('GET /api/alerts/:id returns 404 for non-existent alert id', async () => {
    const fakeId = new mongoose.Types.ObjectId();
    const res = await request(app)
      .get(`/api/alerts/${fakeId}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.statusCode).toEqual(404);
  });

  test('PATCH /api/alerts/:id updates status to acknowledged and sets timestamp with valid CSRF', async () => {
    const alert = await Alert.create({
      severity: 'high', attackType: 'DDoS', prediction: 'DDoS', confidence: 0.99, datasetType: 'cicids2017', modelVersion: 'v1', status: 'open', description: 'DDoS attack'
    });

    const res = await request(app)
      .patch(`/api/alerts/${alert._id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({ status: 'acknowledged' });

    expect(res.statusCode).toEqual(200);
    expect(res.body.data.status).toEqual('acknowledged');
    expect(res.body.data.acknowledgedAt).not.toBeNull();
    expect(res.body.data.datasetType).toEqual('cicids2017');
    expect(res.body.data._id.toString()).toEqual(alert._id.toString());
  });

  test('PATCH /api/alerts/:id rejects acknowledge if CSRF token header is missing (403 CSRF_ERROR)', async () => {
    const alert = await Alert.create({
      severity: 'high', attackType: 'DoS', prediction: 'DoS', confidence: 0.95, datasetType: 'nsl_kdd', modelVersion: 'v1', status: 'open', description: 'DoS attack'
    });

    const res = await request(app)
      .patch(`/api/alerts/${alert._id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      // Omit X-XSRF-TOKEN header
      .send({ status: 'acknowledged' });

    expect(res.statusCode).toEqual(403);
    expect(res.body.error.code).toEqual('CSRF_ERROR');

    // Confirm alert in DB was NOT modified
    const untouched = await Alert.findById(alert._id);
    expect(untouched.status).toEqual('open');
    expect(untouched.acknowledgedAt).toBeNull();
  });

  test('PATCH /api/alerts/:id rejects resolve if CSRF token header is missing (403 CSRF_ERROR)', async () => {
    const alert = await Alert.create({
      severity: 'medium', attackType: 'Probe', prediction: 'Probe', confidence: 0.85, datasetType: 'nsl_kdd', modelVersion: 'v1', status: 'acknowledged', description: 'Probe attempt'
    });

    const res = await request(app)
      .patch(`/api/alerts/${alert._id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      // Omit X-XSRF-TOKEN header
      .send({ status: 'resolved' });

    expect(res.statusCode).toEqual(403);
    expect(res.body.error.code).toEqual('CSRF_ERROR');

    const untouched = await Alert.findById(alert._id);
    expect(untouched.status).toEqual('acknowledged');
    expect(untouched.resolvedAt).toBeNull();
  });

  test('PATCH /api/alerts/:id rejects request with invalid/tampered CSRF token (403 CSRF_ERROR)', async () => {
    const alert = await Alert.create({
      severity: 'low', attackType: 'Probe', prediction: 'Probe', confidence: 0.70, datasetType: 'nsl_kdd', modelVersion: 'v1', status: 'open', description: 'Probe scan'
    });

    const res = await request(app)
      .patch(`/api/alerts/${alert._id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', 'tampered_invalid_csrf_token_value')
      .send({ status: 'acknowledged' });

    expect(res.statusCode).toEqual(403);
    expect(res.body.error.code).toEqual('CSRF_ERROR');
  });

  test('PATCH /api/alerts/:id updates status to resolved and sets resolvedAt timestamp with valid CSRF', async () => {
    const alert = await Alert.create({
      severity: 'high', attackType: 'PortScan', prediction: 'PortScan', confidence: 0.92, datasetType: 'cicids2017', modelVersion: 'v1', status: 'acknowledged', description: 'Port scan attack'
    });

    const res = await request(app)
      .patch(`/api/alerts/${alert._id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({ status: 'resolved' });

    expect(res.statusCode).toEqual(200);
    expect(res.body.data.status).toEqual('resolved');
    expect(res.body.data.resolvedAt).not.toBeNull();
    expect(res.body.data.datasetType).toEqual('cicids2017');
    expect(res.body.data._id.toString()).toEqual(alert._id.toString());
  });
});
