const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const app = require('../src/app');
const mlService = require('../src/services/mlService');
const Log = require('../src/models/Log');
const Alert = require('../src/models/Alert');
const User = require('../src/models/User');
const notificationService = require('../src/services/notificationService');

jest.mock('../src/services/mlService');

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
  adminCsrf = loginRes.body.csrfToken || 'test_csrf';

  notificationService.setTransporter(null);
  notificationService.clearDispatchedAlerts();

  jest.clearAllMocks();
});

describe('POST /api/predictions & GET /api/predictions', () => {
  test('POST /api/predictions rejects invalid datasetType with HTTP 400', async () => {
    const res = await request(app)
      .post('/api/predictions')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({
        datasetType: 'invalid_dataset',
        inputData: { duration: 0 }
      });
    expect(res.statusCode).toEqual(400);
    expect(res.body.error.message).toContain('datasetType');
  });

  test('POST /api/predictions rejects empty inputData with HTTP 400', async () => {
    const res = await request(app)
      .post('/api/predictions')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({
        datasetType: 'nsl_kdd',
        inputData: {}
      });
    expect(res.statusCode).toEqual(400);
    expect(res.body.error.message).toContain('inputData');
  });

  test('POST /api/predictions processes benign prediction (Normal), saves Log, triggers NO alert', async () => {
    mlService.predict.mockResolvedValueOnce({
      dataset_type: 'nsl_kdd',
      model_version: 'NetShield-NSLKDD-XGBoost-v1.0',
      records_processed: 1,
      client_latency_ms: 12.5,
      predictions: [
        {
          record_index: 0,
          prediction: 'Normal',
          prediction_index: 1,
          confidence: 0.998,
          class_probabilities: { Normal: 0.998, DoS: 0.002 }
        }
      ]
    });

    const res = await request(app)
      .post('/api/predictions')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({
        datasetType: 'nsl_kdd',
        inputData: { duration: 0, protocol_type: 'tcp', service: 'http', flag: 'SF' }
      });

    expect(res.statusCode).toEqual(200);
    expect(res.body.success).toBe(true);
    expect(res.body.alert_generated).toBe(false);
    expect(res.body.alert_id).toBeNull();

    // Verify Log document created in MongoDB
    const logs = await Log.find({}).lean();
    expect(logs.length).toEqual(1);
    expect(logs[0].prediction).toEqual('Normal');
    expect(logs[0].datasetType).toEqual('nsl_kdd');

    // Verify NO Alert created
    const alerts = await Alert.find({}).lean();
    expect(alerts.length).toEqual(0);
  });

  test('POST /api/predictions processes attack prediction (DoS), saves Log AND creates Alert', async () => {
    mlService.predict.mockResolvedValueOnce({
      dataset_type: 'nsl_kdd',
      model_version: 'NetShield-NSLKDD-XGBoost-v1.0',
      records_processed: 1,
      client_latency_ms: 15.0,
      predictions: [
        {
          record_index: 0,
          prediction: 'DoS',
          prediction_index: 0,
          confidence: 0.995,
          class_probabilities: { Normal: 0.005, DoS: 0.995 }
        }
      ]
    });

    const res = await request(app)
      .post('/api/predictions')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({
        datasetType: 'nsl_kdd',
        inputData: { duration: 0, protocol_type: 'tcp', service: 'private', flag: 'S0' }
      });

    expect(res.statusCode).toEqual(200);
    expect(res.body.success).toBe(true);
    expect(res.body.alert_generated).toBe(true);
    expect(res.body.alert_id).not.toBeNull();
    expect(res.body.severity).toEqual('high');

    // Verify Log document created
    const logs = await Log.find({}).lean();
    expect(logs.length).toEqual(1);
    expect(logs[0].prediction).toEqual('DoS');

    // Verify Alert document created in MongoDB
    const alerts = await Alert.find({}).lean();
    expect(alerts.length).toEqual(1);
    expect(alerts[0].attackType).toEqual('DoS');
    expect(alerts[0].severity).toEqual('high');
    expect(alerts[0].status).toEqual('open');
  });

  test('GET /api/predictions supports pagination and datasetType filtering', async () => {
    await Log.create([
      { datasetType: 'nsl_kdd', prediction: 'Normal', predictionIndex: 1, confidence: 0.9, modelVersion: 'v1' },
      { datasetType: 'cicids2017', prediction: 'BENIGN', predictionIndex: 0, confidence: 0.95, modelVersion: 'v1' }
    ]);

    const res = await request(app)
      .get('/api/predictions?datasetType=nsl_kdd&page=1&limit=10')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.statusCode).toEqual(200);
    expect(res.body.pagination.total).toEqual(1);
    expect(res.body.data.length).toEqual(1);
    expect(res.body.data[0].datasetType).toEqual('nsl_kdd');
  });

  test('POST /api/predictions with HIGH severity alert automatically dispatches email notification', async () => {
    let dispatchedMail = null;
    const mockTransporter = {
      sendMail: jest.fn().mockImplementation(async (params) => {
        dispatchedMail = params;
        return { messageId: '<automated-alert-msg-789@netshield>' };
      })
    };
    notificationService.setTransporter(mockTransporter);

    mlService.predict.mockResolvedValueOnce({
      dataset_type: 'nsl_kdd',
      model_version: 'NetShield-NSLKDD-XGBoost-v1.0',
      records_processed: 1,
      client_latency_ms: 10.0,
      predictions: [
        {
          record_index: 0,
          prediction: 'DoS',
          prediction_index: 0,
          confidence: 0.99,
          class_probabilities: { Normal: 0.01, DoS: 0.99 }
        }
      ]
    });

    const res = await request(app)
      .post('/api/predictions')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({
        datasetType: 'nsl_kdd',
        inputData: { duration: 0, protocol_type: 'tcp', service: 'http', flag: 'SF' },
        sourceInfo: {
          src_ip: '10.10.10.50',
          dst_ip: '192.168.1.1',
          src_port: 4321,
          dst_port: 80,
          protocol: 'tcp'
        }
      });

    expect(res.statusCode).toEqual(200);
    expect(res.body.alert_generated).toBe(true);
    expect(res.body.severity).toBe('high');

    // Allow background async sendSecurityAlertNotification promise to resolve
    await new Promise((r) => setTimeout(r, 100));

    expect(mockTransporter.sendMail).toHaveBeenCalledTimes(1);
    expect(dispatchedMail.subject).toContain('[NetShield] HIGH Security Alert — DoS');
    expect(dispatchedMail.text).toContain('Source IP: 10.10.10.50');
    expect(dispatchedMail.text).toContain('Destination IP: 192.168.1.1');
    expect(dispatchedMail.text).toContain('10.10.10.50:4321 -> 192.168.1.1:80 [TCP]');
    expect(dispatchedMail.html).toContain('10.10.10.50:4321 &rarr; 192.168.1.1:80 [TCP]');
  });

  test('POST /api/predictions with LOW severity alert (Probe) creates Alert but does NOT send email', async () => {
    const mockTransporter = {
      sendMail: jest.fn()
    };
    notificationService.setTransporter(mockTransporter);

    mlService.predict.mockResolvedValueOnce({
      dataset_type: 'nsl_kdd',
      model_version: 'NetShield-NSLKDD-XGBoost-v1.0',
      records_processed: 1,
      client_latency_ms: 8.0,
      predictions: [
        {
          record_index: 0,
          prediction: 'Probe',
          prediction_index: 2,
          confidence: 0.95,
          class_probabilities: { Normal: 0.05, Probe: 0.95 }
        }
      ]
    });

    const res = await request(app)
      .post('/api/predictions')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({
        datasetType: 'nsl_kdd',
        inputData: { duration: 0, protocol_type: 'icmp', service: 'eco_i', flag: 'SF' }
      });

    expect(res.statusCode).toEqual(200);
    expect(res.body.alert_generated).toBe(true);
    expect(res.body.severity).toBe('low');

    await new Promise((r) => setTimeout(r, 50));
    expect(mockTransporter.sendMail).not.toHaveBeenCalled();
  });

  test('POST /api/predictions gracefully handles email delivery failure without failing alert creation', async () => {
    const mockTransporter = {
      sendMail: jest.fn().mockRejectedValue(new Error('SMTP Transport Network Connection Timeout'))
    };
    notificationService.setTransporter(mockTransporter);

    mlService.predict.mockResolvedValueOnce({
      dataset_type: 'nsl_kdd',
      model_version: 'NetShield-NSLKDD-XGBoost-v1.0',
      records_processed: 1,
      client_latency_ms: 11.0,
      predictions: [
        {
          record_index: 0,
          prediction: 'DoS',
          prediction_index: 0,
          confidence: 0.98,
          class_probabilities: { Normal: 0.02, DoS: 0.98 }
        }
      ]
    });

    const res = await request(app)
      .post('/api/predictions')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({
        datasetType: 'nsl_kdd',
        inputData: { duration: 0, protocol_type: 'tcp', service: 'private', flag: 'S0' }
      });

    // HTTP 200 response must NOT be blocked or failed by SMTP error
    expect(res.statusCode).toEqual(200);
    expect(res.body.success).toBe(true);
    expect(res.body.alert_generated).toBe(true);

    // Alert must still be saved in MongoDB
    const alert = await Alert.findById(res.body.alert_id).lean();
    expect(alert).not.toBeNull();
    expect(alert.severity).toBe('high');
  });

  test('POST /api/predictions (Manual Predict with NO network metadata) renders unknown:N/A fallback', async () => {
    let dispatchedMail = null;
    const mockTransporter = {
      sendMail: jest.fn().mockImplementation(async (params) => {
        dispatchedMail = params;
        return { messageId: '<manual-pred-no-meta@netshield>' };
      })
    };
    notificationService.setTransporter(mockTransporter);

    mlService.predict.mockResolvedValueOnce({
      dataset_type: 'cicids2017',
      model_version: 'NetShield-CICIDS2017-TwoStage-v1.2',
      records_processed: 1,
      client_latency_ms: 15.0,
      predictions: [
        {
          record_index: 0,
          prediction: 'DoS Hulk',
          prediction_index: 4,
          confidence: 0.996,
          class_probabilities: { 'DoS Hulk': 0.996, BENIGN: 0.004 }
        }
      ]
    });

    // Submitting with only tabular feature input and groundTruth, no network coordinates
    const res = await request(app)
      .post('/api/predictions')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({
        datasetType: 'cicids2017',
        inputData: { "Destination Port": 80, "Flow Duration": 1878 },
        sourceInfo: { groundTruth: 'DoS Hulk' }
      });

    expect(res.statusCode).toEqual(200);
    expect(res.body.alert_generated).toBe(true);

    await new Promise((r) => setTimeout(r, 100));

    expect(mockTransporter.sendMail).toHaveBeenCalledTimes(1);
    expect(dispatchedMail.text).toContain('unknown:N/A -> unknown:N/A [N/A]');
    expect(dispatchedMail.html).toContain('unknown:N/A &rarr; unknown:N/A [N/A]');

    const savedAlert = await Alert.findById(res.body.alert_id).lean();
    expect(savedAlert.sourceInfo.groundTruth).toBe('DoS Hulk');
    expect(savedAlert.sourceInfo.src_ip).toBeUndefined();
  });

  test('POST /api/predictions (Manual Predict WITH network metadata) preserves authentic coordinates', async () => {
    let dispatchedMail = null;
    const mockTransporter = {
      sendMail: jest.fn().mockImplementation(async (params) => {
        dispatchedMail = params;
        return { messageId: '<manual-pred-with-meta@netshield>' };
      })
    };
    notificationService.setTransporter(mockTransporter);

    mlService.predict.mockResolvedValueOnce({
      dataset_type: 'cicids2017',
      model_version: 'NetShield-CICIDS2017-TwoStage-v1.2',
      records_processed: 1,
      client_latency_ms: 15.0,
      predictions: [
        {
          record_index: 0,
          prediction: 'DoS Hulk',
          prediction_index: 4,
          confidence: 0.996,
          class_probabilities: { 'DoS Hulk': 0.996, BENIGN: 0.004 }
        }
      ]
    });

    const res = await request(app)
      .post('/api/predictions')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({
        datasetType: 'cicids2017',
        inputData: { "Flow Duration": 1878 },
        sourceInfo: {
          groundTruth: 'DoS Hulk',
          src_ip: '192.168.10.5',
          dst_ip: '192.168.10.100',
          src_port: 48999,
          dst_port: 80,
          protocol: 'TCP'
        }
      });

    expect(res.statusCode).toEqual(200);
    expect(res.body.alert_generated).toBe(true);

    await new Promise((r) => setTimeout(r, 100));

    expect(mockTransporter.sendMail).toHaveBeenCalledTimes(1);
    expect(dispatchedMail.text).toContain('192.168.10.5:48999 -> 192.168.10.100:80 [TCP]');
    expect(dispatchedMail.html).toContain('192.168.10.5:48999 &rarr; 192.168.10.100:80 [TCP]');

    const savedAlert = await Alert.findById(res.body.alert_id).lean();
    expect(savedAlert.sourceInfo.src_ip).toBe('192.168.10.5');
    expect(savedAlert.sourceInfo.dst_ip).toBe('192.168.10.100');
    expect(savedAlert.sourceInfo.src_port).toBe(48999);
    expect(savedAlert.sourceInfo.dst_port).toBe(80);
    expect(savedAlert.sourceInfo.protocol).toBe('TCP');
  });
});

