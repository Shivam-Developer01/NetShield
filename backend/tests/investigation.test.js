const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const app = require('../src/app');
const User = require('../src/models/User');
const Log = require('../src/models/Log');
const Alert = require('../src/models/Alert');

jest.setTimeout(30000);

let mongoServer;
let adminCookie, viewerCookie;
let adminToken, viewerToken;
let testAlert;

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  await mongoose.connect(mongoServer.getUri());
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

beforeEach(async () => {
  await User.deleteMany({});
  await Log.deleteMany({});
  await Alert.deleteMany({});

  const getCookieString = (res) => {
    const cookies = res.headers['set-cookie'] || [];
    const tokenMatch = cookies.find(c => c.startsWith('netshield_token='));
    const tokenStr = tokenMatch ? tokenMatch.split(';')[0] : '';
    const xsrfStr = `XSRF-TOKEN=${res.body.csrfToken}`;
    return `${tokenStr}; ${xsrfStr}`;
  };

  // Register Admin
  await request(app).post('/api/auth/register').send({
    username: 'admin_invest',
    email: 'admin@invest.com',
    password: 'AdminPassword123!'
  });
  await User.findOneAndUpdate({ email: 'admin@invest.com' }, { role: 'ADMIN' });
  const adminLogin = await request(app).post('/api/auth/login').send({
    email: 'admin@invest.com',
    password: 'AdminPassword123!'
  });
  adminCookie = getCookieString(adminLogin);
  adminToken = adminLogin.body.token;

  // Register Viewer
  await request(app).post('/api/auth/register').send({
    username: 'viewer_invest',
    email: 'viewer@invest.com',
    password: 'ViewerPassword123!'
  });
  const viewerLogin = await request(app).post('/api/auth/login').send({
    email: 'viewer@invest.com',
    password: 'ViewerPassword123!'
  });
  viewerCookie = getCookieString(viewerLogin);
  viewerToken = viewerLogin.body.token;

  // Create sample alert and prediction log
  testAlert = await Alert.create({
    timestamp: new Date(),
    severity: 'high',
    attackType: 'DoS',
    prediction: 'neptune',
    confidence: 0.99,
    datasetType: 'nsl_kdd',
    modelVersion: 'NetShield-NSLKDD-XGBoost-v1.0',
    status: 'open',
    description: 'Neptune DoS Attack Detected'
  });

  await Log.create({
    timestamp: new Date(),
    datasetType: 'nsl_kdd',
    prediction: 'neptune',
    predictionIndex: 0,
    confidence: 0.99,
    modelVersion: 'NetShield-NSLKDD-XGBoost-v1.0',
    recordsProcessed: 1,
    processingLatencyMs: 15.5
  });
});

describe('Phase 15 — SOC Investigation API Suite', () => {
  test('1. Unauthenticated investigation request returns HTTP 401', async () => {
    const res = await request(app).get(`/api/investigations/alerts/${testAlert._id}`);
    expect(res.statusCode).toBe(401);
  });

  test('2. Existing alert investigation returns HTTP 200 with metadata & timeline', async () => {
    const res = await request(app)
      .get(`/api/investigations/alerts/${testAlert._id}`)
      .set('Authorization', `Bearer ${viewerToken}`)
      .set('Cookie', viewerCookie);
    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.alert.id).toBe(testAlert._id.toString());
    expect(res.body.data.alert.prediction).toBe('neptune');
    expect(Array.isArray(res.body.data.timeline)).toBe(true);
    expect(res.body.data.timeline.length).toBeGreaterThan(0);
  });

  test('3. Non-existent alert ID returns HTTP 404', async () => {
    const fakeId = new mongoose.Types.ObjectId();
    const res = await request(app)
      .get(`/api/investigations/alerts/${fakeId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', adminCookie);
    expect(res.statusCode).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
  });

  test('4. Investigation response excludes sensitive credentials', async () => {
    const res = await request(app)
      .get(`/api/investigations/alerts/${testAlert._id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', adminCookie);
    expect(res.statusCode).toBe(200);
    const bodyStr = JSON.stringify(res.body);
    expect(bodyStr).not.toContain('password');
    expect(bodyStr).not.toContain('jwtSecret');
  });

  test('5. Related activity endpoint returns bounded events around alert', async () => {
    const res = await request(app)
      .get(`/api/investigations/alerts/${testAlert._id}/activity?timeWindowMinutes=15`)
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', adminCookie);
    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.timeWindowMinutes).toBe(15);
    expect(Array.isArray(res.body.data.logs)).toBe(true);
  });

  test('6. Related activity endpoint for non-existent alert returns HTTP 404', async () => {
    const fakeId = new mongoose.Types.ObjectId();
    const res = await request(app)
      .get(`/api/investigations/alerts/${fakeId}/activity`)
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', adminCookie);
    expect(res.statusCode).toBe(404);
  });
});
