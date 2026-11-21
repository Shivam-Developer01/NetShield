const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const app = require('../src/app');
const Log = require('../src/models/Log');
const Alert = require('../src/models/Alert');
const User = require('../src/models/User');

let mongoServer;
let adminToken;

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
  await Log.deleteMany({});
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
});

describe('System Metrics API Endpoint', () => {
  beforeEach(async () => {
    // Seed multi-dataset records
    await Log.create([
      // NSL-KDD logs
      { datasetType: 'nsl_kdd', prediction: 'Normal', predictionIndex: 1, confidence: 0.9, modelVersion: 'v1', processingLatencyMs: 10 },
      { datasetType: 'nsl_kdd', prediction: 'Normal', predictionIndex: 1, confidence: 0.9, modelVersion: 'v1', processingLatencyMs: 12 },
      { datasetType: 'nsl_kdd', prediction: 'DoS', predictionIndex: 0, confidence: 0.95, modelVersion: 'v1', processingLatencyMs: 14 },
      // CICIDS2017 logs
      { datasetType: 'cicids2017', prediction: 'BENIGN', predictionIndex: 0, confidence: 0.99, modelVersion: 'v1.2', processingLatencyMs: 20 },
      { datasetType: 'cicids2017', prediction: 'BENIGN', predictionIndex: 0, confidence: 0.98, modelVersion: 'v1.2', processingLatencyMs: 30 },
      { datasetType: 'cicids2017', prediction: 'DDoS', predictionIndex: 2, confidence: 0.97, modelVersion: 'v1.2', processingLatencyMs: 40 },
      { datasetType: 'cicids2017', prediction: 'PortScan', predictionIndex: 3, confidence: 0.96, modelVersion: 'v1.2', processingLatencyMs: 50 }
    ]);

    await Alert.create([
      { severity: 'high', attackType: 'DoS', prediction: 'DoS', confidence: 0.95, datasetType: 'nsl_kdd', modelVersion: 'v1', status: 'open', description: 'NSL DoS alert' },
      { severity: 'critical', attackType: 'DDoS', prediction: 'DDoS', confidence: 0.97, datasetType: 'cicids2017', modelVersion: 'v1.2', status: 'open', description: 'CICIDS DDoS alert' },
      { severity: 'medium', attackType: 'PortScan', prediction: 'PortScan', confidence: 0.96, datasetType: 'cicids2017', modelVersion: 'v1.2', status: 'acknowledged', description: 'CICIDS PortScan alert' },
      { severity: 'low', attackType: 'PortScan', prediction: 'PortScan', confidence: 0.90, datasetType: 'cicids2017', modelVersion: 'v1.2', status: 'resolved', description: 'Resolved alert' }
    ]);
  });

  test('GET /api/metrics (unfiltered) calculates global aggregated stats across all datasets', async () => {
    const res = await request(app)
      .get('/api/metrics')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.statusCode).toEqual(200);
    expect(res.body.data.datasetType).toEqual('all');
    expect(res.body.data.measured.totalFlows).toEqual(7);
    expect(res.body.data.measured.benignFlows).toEqual(4); // 2 Normal + 2 BENIGN
    expect(res.body.data.measured.maliciousFlows).toEqual(3); // 1 DoS + 1 DDoS + 1 PortScan
    expect(res.body.data.calculated.detectionRate).toEqual(42.86);
    expect(res.body.data.measured.activeAlerts).toEqual(3); // 1 open + 1 open + 1 acknowledged
  });

  test('GET /api/metrics?datasetType=all behaves identically to unfiltered', async () => {
    const res = await request(app)
      .get('/api/metrics?datasetType=all')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.statusCode).toEqual(200);
    expect(res.body.data.datasetType).toEqual('all');
    expect(res.body.data.measured.totalFlows).toEqual(7);
    expect(res.body.data.measured.benignFlows).toEqual(4);
    expect(res.body.data.measured.maliciousFlows).toEqual(3);
    expect(res.body.data.measured.activeAlerts).toEqual(3);
  });

  test('GET /api/metrics?datasetType=nsl_kdd scopes strictly to NSL-KDD metrics', async () => {
    const res = await request(app)
      .get('/api/metrics?datasetType=nsl_kdd')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.statusCode).toEqual(200);
    expect(res.body.data.datasetType).toEqual('nsl_kdd');
    expect(res.body.data.measured.totalFlows).toEqual(3);
    expect(res.body.data.measured.benignFlows).toEqual(2);
    expect(res.body.data.measured.maliciousFlows).toEqual(1);
    expect(res.body.data.calculated.detectionRate).toEqual(33.33);
    expect(res.body.data.measured.activeAlerts).toEqual(1);
    expect(res.body.data.measured.processingLatencyMs).toEqual(12); // (10+12+14)/3
  });

  test('GET /api/metrics?datasetType=cicids2017 scopes strictly to CICIDS2017 metrics and recognizes BENIGN', async () => {
    const res = await request(app)
      .get('/api/metrics?datasetType=cicids2017')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.statusCode).toEqual(200);
    expect(res.body.data.datasetType).toEqual('cicids2017');
    expect(res.body.data.measured.totalFlows).toEqual(4);
    expect(res.body.data.measured.benignFlows).toEqual(2); // 2 BENIGN records
    expect(res.body.data.measured.maliciousFlows).toEqual(2); // 1 DDoS + 1 PortScan
    expect(res.body.data.calculated.detectionRate).toEqual(50.0);
    expect(res.body.data.measured.activeAlerts).toEqual(2); // 1 open + 1 acknowledged
    expect(res.body.data.measured.processingLatencyMs).toEqual(35); // (20+30+40+50)/4
  });

  test('GET /api/metrics?datasetType=invalid_dataset returns 400 Bad Request', async () => {
    const res = await request(app)
      .get('/api/metrics?datasetType=invalid_dataset')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.statusCode).toEqual(400);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toMatch(/Invalid datasetType/);
  });
});
