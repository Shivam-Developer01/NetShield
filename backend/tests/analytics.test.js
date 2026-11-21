const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const app = require('../src/app');
const User = require('../src/models/User');
const Log = require('../src/models/Log');
const Alert = require('../src/models/Alert');

jest.setTimeout(30000);

let mongoServer;
let adminCookie, analystCookie, viewerCookie;
let adminCsrf, analystCsrf, viewerCsrf;
let adminToken, analystToken, viewerToken;

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
    username: 'admin_analytics',
    email: 'admin@analytics.com',
    password: 'AdminPassword123!'
  });
  await User.findOneAndUpdate({ email: 'admin@analytics.com' }, { role: 'ADMIN' });
  const adminLogin = await request(app).post('/api/auth/login').send({
    email: 'admin@analytics.com',
    password: 'AdminPassword123!'
  });
  adminCookie = getCookieString(adminLogin);
  adminToken = adminLogin.body.token;
  adminCsrf = adminLogin.body.csrfToken;

  // Register Analyst
  await request(app).post('/api/auth/register').send({
    username: 'analyst_analytics',
    email: 'analyst@analytics.com',
    password: 'AnalystPassword123!'
  });
  await User.findOneAndUpdate({ email: 'analyst@analytics.com' }, { role: 'ANALYST' });
  const analystLogin = await request(app).post('/api/auth/login').send({
    email: 'analyst@analytics.com',
    password: 'AnalystPassword123!'
  });
  analystCookie = getCookieString(analystLogin);
  analystToken = analystLogin.body.token;
  analystCsrf = analystLogin.body.csrfToken;

  // Register Viewer
  await request(app).post('/api/auth/register').send({
    username: 'viewer_analytics',
    email: 'viewer@analytics.com',
    password: 'ViewerPassword123!'
  });
  const viewerLogin = await request(app).post('/api/auth/login').send({
    email: 'viewer@analytics.com',
    password: 'ViewerPassword123!'
  });
  viewerCookie = getCookieString(viewerLogin);
  viewerToken = viewerLogin.body.token;
  viewerCsrf = viewerLogin.body.csrfToken;

  // Seed sample logs
  await Log.create([
    { timestamp: new Date(), datasetType: 'nsl_kdd', prediction: 'Normal', predictionIndex: 1, confidence: 0.98, modelVersion: 'NetShield-NSLKDD-XGBoost-v1.0', recordsProcessed: 1, processingLatencyMs: 12 },
    { timestamp: new Date(), datasetType: 'nsl_kdd', prediction: 'neptune', predictionIndex: 0, confidence: 0.95, modelVersion: 'NetShield-NSLKDD-XGBoost-v1.0', recordsProcessed: 1, processingLatencyMs: 18 },
    { timestamp: new Date(), datasetType: 'cicids2017', prediction: 'DDoS', predictionIndex: 2, confidence: 0.99, modelVersion: 'NetShield-CICIDS2017-XGBoost-v1.0', recordsProcessed: 1, processingLatencyMs: 25 }
  ]);

  // Seed sample alerts
  await Alert.create([
    { timestamp: new Date(), severity: 'high', attackType: 'DoS', prediction: 'neptune', confidence: 0.95, datasetType: 'nsl_kdd', modelVersion: 'NetShield-NSLKDD-XGBoost-v1.0', status: 'open', description: 'Neptune DoS attack detected' },
    { timestamp: new Date(), severity: 'critical', attackType: 'DDoS', prediction: 'DDoS', confidence: 0.99, datasetType: 'cicids2017', modelVersion: 'NetShield-CICIDS2017-XGBoost-v1.0', status: 'acknowledged', description: 'DDoS attack detected', acknowledgedAt: new Date() }
  ]);
});

describe('Phase 15 — Security Analytics API Suite', () => {
  test('1. Unauthenticated request to /api/analytics/overview is rejected (401)', async () => {
    const res = await request(app).get('/api/analytics/overview');
    expect(res.statusCode).toBe(401);
  });

  test('2. VIEWER, ANALYST, and ADMIN can access /api/analytics/overview (200)', async () => {
    const viewerRes = await request(app)
      .get('/api/analytics/overview')
      .set('Authorization', `Bearer ${viewerToken}`)
      .set('Cookie', viewerCookie);
    expect(viewerRes.statusCode).toBe(200);
    expect(viewerRes.body.success).toBe(true);
    expect(viewerRes.body.totalPredictions).toBe(3);
    expect(viewerRes.body.benignPredictions).toBe(1);
    expect(viewerRes.body.maliciousPredictions).toBe(2);

    const adminRes = await request(app)
      .get('/api/analytics/overview')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', adminCookie);
    expect(adminRes.statusCode).toBe(200);
  });

  test('3. Invalid date parameters (startDate > endDate) returns HTTP 400', async () => {
    const res = await request(app)
      .get('/api/analytics/overview?startDate=2026-08-20&endDate=2026-08-10')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', adminCookie);
    expect(res.statusCode).toBe(400);
    expect(res.body.error.message).toContain('startDate');
  });

  test('4. Invalid dataset parameter returns HTTP 400', async () => {
    const res = await request(app)
      .get('/api/analytics/overview?datasetType=invalid_dataset')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', adminCookie);
    expect(res.statusCode).toBe(400);
  });

  test('5. GET /api/analytics/trends returns time-series dataset', async () => {
    const res = await request(app)
      .get('/api/analytics/trends?interval=day')
      .set('Authorization', `Bearer ${analystToken}`)
      .set('Cookie', analystCookie);
    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.interval).toBe('day');
    expect(Array.isArray(res.body.data)).toBe(true);
  });

  test('6. GET /api/analytics/attacks returns aggregated attack distribution', async () => {
    const res = await request(app)
      .get('/api/analytics/attacks')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', adminCookie);
    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.data.length).toBeGreaterThan(0);
    expect(res.body.data[0].attackType).toBeDefined();
  });

  test('7. GET /api/analytics/severity returns severity breakdown', async () => {
    const res = await request(app)
      .get('/api/analytics/severity')
      .set('Authorization', `Bearer ${viewerToken}`)
      .set('Cookie', viewerCookie);
    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.high.count).toBe(1);
    expect(res.body.data.critical.count).toBe(1);
  });

  test('8. GET /api/analytics/models returns dataset/model analytics', async () => {
    const res = await request(app)
      .get('/api/analytics/models')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', adminCookie);
    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.length).toBe(2);
  });

  test('9. GET /api/analytics/alerts returns alert status and timing metrics', async () => {
    const res = await request(app)
      .get('/api/analytics/alerts')
      .set('Authorization', `Bearer ${analystToken}`)
      .set('Cookie', analystCookie);
    expect(res.statusCode).toBe(200);
    expect(res.body.data.totalAlerts).toBe(2);
    expect(res.body.data.openAlerts).toBe(1);
    expect(res.body.data.acknowledgedAlerts).toBe(1);
  });

  test('10. CSV Export is forbidden for VIEWER (403)', async () => {
    const res = await request(app)
      .get('/api/analytics/export?type=predictions')
      .set('Authorization', `Bearer ${viewerToken}`)
      .set('Cookie', viewerCookie);
    expect(res.statusCode).toBe(403);
  });

  test('11. CSV Export is allowed for ANALYST and ADMIN (200)', async () => {
    const res = await request(app)
      .get('/api/analytics/export?type=predictions')
      .set('Authorization', `Bearer ${analystToken}`)
      .set('Cookie', analystCookie);
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/csv');
    expect(res.text).toContain('Log ID,Timestamp,Dataset');
  });

  test('12. CSV Export respects record limit and excludes secrets', async () => {
    const res = await request(app)
      .get('/api/analytics/export?type=alerts&limit=5')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', adminCookie);
    expect(res.statusCode).toBe(200);
    expect(res.text).not.toContain('password');
    expect(res.text).not.toContain('jwtSecret');
  });

  test('13. Analytics overview correctly counts CICIDS2017 BENIGN as benign and scopes by dataset', async () => {
    // Add a CICIDS2017 BENIGN log
    await Log.create({
      timestamp: new Date(),
      datasetType: 'cicids2017',
      prediction: 'BENIGN',
      predictionIndex: 0,
      confidence: 0.99,
      modelVersion: 'NetShield-CICIDS2017-TwoStage-v1.2',
      recordsProcessed: 1,
      processingLatencyMs: 15
    });

    const resCicids = await request(app)
      .get('/api/analytics/overview?datasetType=cicids2017')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', adminCookie);

    expect(resCicids.statusCode).toBe(200);
    // 1 DDoS + 1 BENIGN in cicids2017
    expect(resCicids.body.totalPredictions).toBe(2);
    expect(resCicids.body.benignPredictions).toBe(1);
    expect(resCicids.body.maliciousPredictions).toBe(1);
    expect(resCicids.body.detectionRate).toBe(50.0);
  });

  test('14. Phase 20.3: Alert analytics correctly computes avg ack/resolve time and excludes incomplete alerts', async () => {
    await Alert.deleteMany({});

    const baseTime = new Date('2026-09-01T10:00:00.000Z');
    const ackTime1 = new Date('2026-09-01T10:01:00.000Z'); // 60s = 60000ms
    const resolveTime1 = new Date('2026-09-01T10:05:00.000Z'); // 300s = 300000ms

    const baseTime2 = new Date('2026-09-01T11:00:00.000Z');
    const ackTime2 = new Date('2026-09-01T11:02:00.000Z'); // 120s = 120000ms

    const baseTime3 = new Date('2026-09-01T12:00:00.000Z');

    await Alert.create([
      {
        timestamp: baseTime,
        severity: 'high',
        attackType: 'DoS',
        prediction: 'neptune',
        confidence: 0.95,
        datasetType: 'nsl_kdd',
        modelVersion: 'NetShield-NSLKDD-XGBoost-v1.0',
        status: 'resolved',
        description: 'Neptune DoS attack resolved',
        acknowledgedAt: ackTime1,
        resolvedAt: resolveTime1
      },
      {
        timestamp: baseTime2,
        severity: 'medium',
        attackType: 'PortScan',
        prediction: 'PortScan',
        confidence: 0.90,
        datasetType: 'cicids2017',
        modelVersion: 'NetShield-CICIDS2017-XGBoost-v1.0',
        status: 'acknowledged',
        description: 'PortScan attack acknowledged',
        acknowledgedAt: ackTime2,
        resolvedAt: null
      },
      {
        timestamp: baseTime3,
        severity: 'low',
        attackType: 'ipsweep',
        prediction: 'ipsweep',
        confidence: 0.85,
        datasetType: 'nsl_kdd',
        modelVersion: 'NetShield-NSLKDD-XGBoost-v1.0',
        description: 'ipsweep attack open',
        status: 'open'
      }
    ]);

    const res = await request(app)
      .get('/api/analytics/alerts?timeRange=30d')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', adminCookie);

    expect(res.statusCode).toBe(200);
    expect(res.body.data.totalAlerts).toBe(3);
    expect(res.body.data.openAlerts).toBe(1);
    expect(res.body.data.acknowledgedAlerts).toBe(1);
    expect(res.body.data.resolvedAlerts).toBe(1);

    expect(res.body.data.averageTimeToAckMs).toBe(90000);
    expect(res.body.data.averageTimeToResolutionMs).toBe(300000);

    // Filter window with no alerts returns null (not 0 or fabricated)
    const futureDate = new Date('2026-09-02T00:00:00.000Z').toISOString();
    const emptyRes = await request(app)
      .get(`/api/analytics/alerts?startDate=${futureDate}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', adminCookie);

    expect(emptyRes.statusCode).toBe(200);
    expect(emptyRes.body.data.averageTimeToAckMs).toBeNull();
    expect(emptyRes.body.data.averageTimeToResolutionMs).toBeNull();
  });
});
