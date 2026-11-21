const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const app = require('../src/app');
const Setting = require('../src/models/Setting');
const User = require('../src/models/User');
const Log = require('../src/models/Log');
const Alert = require('../src/models/Alert');
const { enforceLogRetention } = require('../src/services/retentionService');
const settingsService = require('../src/services/settingsService');
const mlService = require('../src/services/mlService');

jest.mock('../src/services/mlService');

let mongoServer;
let adminToken;
let adminCsrf;
let viewerToken;
let viewerCsrf;

jest.setTimeout(30000);

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  const mongoUri = mongoServer.getUri();
  await mongoose.connect(mongoUri);
}, 30000);

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

beforeEach(async () => {
  await Setting.deleteMany({});
  await User.deleteMany({});
  await Log.deleteMany({});
  await Alert.deleteMany({});
  settingsService.invalidateCache();

  // 1. Create Admin
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

  // 2. Create Viewer
  await request(app).post('/api/auth/register').send({
    username: 'viewer',
    email: 'viewer@test.com',
    password: 'Password123!'
  });
  const viewerLogin = await request(app).post('/api/auth/login').send({
    email: 'viewer@test.com',
    password: 'Password123!'
  });
  viewerToken = viewerLogin.body.token;
  viewerCsrf = viewerLogin.body.csrfToken || 'test_csrf_viewer';

  mlService.predict = jest.fn().mockResolvedValue({
    dataset_type: 'nsl_kdd',
    model_version: 'test-v1',
    records_processed: 1,
    client_latency_ms: 10,
    predictions: [
      {
        record_index: 0,
        prediction: 'Normal',
        prediction_index: 1,
        confidence: 0.99,
        class_probabilities: { Normal: 0.99, DoS: 0.01 }
      }
    ]
  });
});

describe('Settings API & Behavioral Integrity Suite', () => {
  test('GET /api/settings seeds and returns all 4 default settings', async () => {
    const res = await request(app)
      .get('/api/settings')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.statusCode).toEqual(200);
    expect(res.body.data.length).toBe(4);
    const keys = res.body.data.map(s => s.key);
    expect(keys).toContain('alertThresholdConfidence');
    expect(keys).toContain('enableAutoResolution');
    expect(keys).toContain('maxLogRetentionDays');
    expect(keys).toContain('systemNotificationEmail');
  });

  test('PATCH /api/settings/alertThresholdConfidence validates range and updates value', async () => {
    // Valid update
    const res = await request(app)
      .patch('/api/settings/alertThresholdConfidence')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({ value: 85, description: 'Updated threshold to 85%' });

    expect(res.statusCode).toEqual(200);
    expect(res.body.data.key).toEqual('alertThresholdConfidence');
    expect(res.body.data.value).toEqual(85);

    // Negative value rejected
    const resNeg = await request(app)
      .patch('/api/settings/alertThresholdConfidence')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({ value: -10 });
    expect(resNeg.statusCode).toEqual(400);

    // Value > 100 rejected
    const resHigh = await request(app)
      .patch('/api/settings/alertThresholdConfidence')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({ value: 150 });
    expect(resHigh.statusCode).toEqual(400);

    // String rejected
    const resStr = await request(app)
      .patch('/api/settings/alertThresholdConfidence')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({ value: 'high' });
    expect(resStr.statusCode).toEqual(400);
  });

  test('PATCH /api/settings/enableAutoResolution validates boolean and updates value', async () => {
    const res = await request(app)
      .patch('/api/settings/enableAutoResolution')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({ value: true });

    expect(res.statusCode).toEqual(200);
    expect(res.body.data.value).toBe(true);

    // Non-boolean rejected
    const resBad = await request(app)
      .patch('/api/settings/enableAutoResolution')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({ value: 'yes' });
    expect(resBad.statusCode).toEqual(400);
  });

  test('PATCH /api/settings/maxLogRetentionDays validates integer days and updates value', async () => {
    const res = await request(app)
      .patch('/api/settings/maxLogRetentionDays')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({ value: 60 });

    expect(res.statusCode).toEqual(200);
    expect(res.body.data.value).toBe(60);

    // Zero rejected
    const resZero = await request(app)
      .patch('/api/settings/maxLogRetentionDays')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({ value: 0 });
    expect(resZero.statusCode).toEqual(400);

    // Float rejected
    const resFloat = await request(app)
      .patch('/api/settings/maxLogRetentionDays')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({ value: 12.5 });
    expect(resFloat.statusCode).toEqual(400);
  });

  test('PATCH /api/settings/systemNotificationEmail validates email syntax and updates value', async () => {
    const res = await request(app)
      .patch('/api/settings/systemNotificationEmail')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({ value: 'soc-team@enterprise.com' });

    expect(res.statusCode).toEqual(200);
    expect(res.body.data.value).toBe('soc-team@enterprise.com');

    // Invalid email rejected
    const resBad = await request(app)
      .patch('/api/settings/systemNotificationEmail')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({ value: 'not-an-email' });
    expect(resBad.statusCode).toEqual(400);
  });

  test('RBAC: VIEWER role cannot update settings (403 Forbidden)', async () => {
    const res = await request(app)
      .patch('/api/settings/alertThresholdConfidence')
      .set('Authorization', `Bearer ${viewerToken}`)
      .set('Cookie', [`netshield_token=${viewerToken}`, `XSRF-TOKEN=${viewerCsrf}`])
      .set('X-XSRF-TOKEN', viewerCsrf)
      .send({ value: 90 });

    expect(res.statusCode).toEqual(403);
  });

  test('CSRF: missing X-XSRF-TOKEN rejected on state-changing request', async () => {
    const res = await request(app)
      .patch('/api/settings/alertThresholdConfidence')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ value: 90 });

    expect(res.statusCode).toEqual(403);
  });

  test('POST /api/settings/notify-digest dynamically reads configured email and formats digest', async () => {
    // Configure specific email
    await request(app)
      .patch('/api/settings/systemNotificationEmail')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({ value: 'alerts-lead@soc.security' });

    const res = await request(app)
      .post('/api/settings/notify-digest')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf);

    expect(res.statusCode).toEqual(200);
    expect(res.body.data.recipient).toBe('alerts-lead@soc.security');
    expect(res.body.data.transport).toBe('TEST_STUB_NO_SMTP');
  });

  test('Retention service prunes only logs older than cutoff while preserving recent logs and alerts', async () => {
    const oldDate = new Date(Date.now() - 40 * 24 * 60 * 60 * 1000);
    const recentDate = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000);

    const oldLog = await Log.create({
      timestamp: oldDate,
      datasetType: 'nsl_kdd',
      prediction: 'Normal',
      predictionIndex: 0,
      confidence: 0.99,
      modelVersion: 'test-v1'
    });

    const recentLog = await Log.create({
      timestamp: recentDate,
      datasetType: 'nsl_kdd',
      prediction: 'Normal',
      predictionIndex: 0,
      confidence: 0.99,
      modelVersion: 'test-v1'
    });

    const alert = await Alert.create({
      timestamp: oldDate,
      severity: 'high',
      attackType: 'DoS',
      prediction: 'DoS',
      confidence: 0.95,
      datasetType: 'nsl_kdd',
      modelVersion: 'test-v1',
      status: 'open',
      description: 'Persistent alert'
    });

    const result = await enforceLogRetention(30);
    expect(result.deletedCount).toBe(1);

    const checkOld = await Log.findById(oldLog._id);
    expect(checkOld).toBeNull();

    const checkRecent = await Log.findById(recentLog._id);
    expect(checkRecent).not.toBeNull();

    const checkAlert = await Alert.findById(alert._id);
    expect(checkAlert).not.toBeNull();
  });

  test('Auto-resolution correlation safety: benign flow with different flow_id does NOT resolve Alert A or Alert B sharing same src_ip', async () => {
    // Enable auto-resolution
    await request(app)
      .patch('/api/settings/enableAutoResolution')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({ value: true });

    // Create Alert A with src_ip: '192.168.1.105', flow_id: 'FLOW-A'
    const alertA = await Alert.create({
      timestamp: new Date(),
      severity: 'high',
      attackType: 'DoS',
      prediction: 'DoS',
      confidence: 0.95,
      datasetType: 'nsl_kdd',
      modelVersion: 'test-v1',
      status: 'open',
      description: 'Threat alert A',
      sourceInfo: { src_ip: '192.168.1.105', flow_id: 'FLOW-A' }
    });

    // Create Alert B with same src_ip: '192.168.1.105', flow_id: 'FLOW-B'
    const alertB = await Alert.create({
      timestamp: new Date(),
      severity: 'high',
      attackType: 'PortScan',
      prediction: 'PortScan',
      confidence: 0.92,
      datasetType: 'nsl_kdd',
      modelVersion: 'test-v1',
      status: 'open',
      description: 'Threat alert B',
      sourceInfo: { src_ip: '192.168.1.105', flow_id: 'FLOW-B' }
    });

    // Ingest benign flow with SAME src_ip ('192.168.1.105') but DIFFERENT flow_id ('FLOW-C')
    // We simulate processSinglePrediction by calling /api/predictions with a normal sample
    // Using supertest to hit /api/predictions
    const resBenignC = await request(app)
      .post('/api/predictions')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({
        datasetType: 'nsl_kdd',
        inputData: {
          duration: 0,
          protocol_type: 'tcp',
          service: 'http',
          flag: 'SF',
          src_bytes: 215,
          dst_bytes: 4500,
          land: 0,
          wrong_fragment: 0,
          urgent: 0,
          hot: 0,
          num_failed_logins: 0,
          logged_in: 1,
          num_compromised: 0,
          root_shell: 0,
          su_attempted: 0,
          num_root: 0,
          num_file_creations: 0,
          num_shells: 0,
          num_access_files: 0,
          num_outbound_cmds: 0,
          is_host_login: 0,
          is_guest_login: 0,
          count: 1,
          srv_count: 1,
          serror_rate: 0,
          srv_serror_rate: 0,
          rerror_rate: 0,
          srv_rerror_rate: 0,
          same_srv_rate: 1,
          diff_srv_rate: 0,
          srv_diff_host_rate: 0,
          dst_host_count: 1,
          dst_host_srv_count: 1,
          dst_host_same_srv_rate: 1,
          dst_host_diff_srv_rate: 0,
          dst_host_same_src_port_rate: 1,
          dst_host_srv_diff_host_rate: 0,
          dst_host_serror_rate: 0,
          dst_host_srv_serror_rate: 0,
          dst_host_rerror_rate: 0,
          dst_host_srv_rerror_rate: 0
        },
        sourceInfo: { src_ip: '192.168.1.105', flow_id: 'FLOW-C' }
      });

    expect(resBenignC.statusCode).toEqual(200);

    // Verify NEITHER Alert A nor Alert B were resolved
    const freshA = await Alert.findById(alertA._id);
    const freshB = await Alert.findById(alertB._id);
    expect(freshA.status).toEqual('open');
    expect(freshA.resolvedAt).toBeNull();
    expect(freshB.status).toEqual('open');
    expect(freshB.resolvedAt).toBeNull();

    // Now send benign flow matching EXACTLY FLOW-A
    const resBenignA = await request(app)
      .post('/api/predictions')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({
        datasetType: 'nsl_kdd',
        inputData: {
          duration: 0,
          protocol_type: 'tcp',
          service: 'http',
          flag: 'SF',
          src_bytes: 215,
          dst_bytes: 4500,
          count: 1,
          srv_count: 1,
          same_srv_rate: 1,
          diff_srv_rate: 0,
          dst_host_count: 1,
          dst_host_srv_count: 1
        },
        sourceInfo: { src_ip: '192.168.1.105', flow_id: 'FLOW-A' }
      });

    expect(resBenignA.statusCode).toEqual(200);

    // Verify Alert A IS resolved with resolvedAt populated
    const freshA2 = await Alert.findById(alertA._id);
    expect(freshA2.status).toEqual('resolved');
    expect(freshA2.resolvedAt).not.toBeNull();
    expect(freshA2.description).toContain('[Auto-resolved: benign traffic resumed for flow FLOW-A]');

    // Verify Alert B remains OPEN
    const freshB2 = await Alert.findById(alertB._id);
    expect(freshB2.status).toEqual('open');
    expect(freshB2.resolvedAt).toBeNull();
  });

  test('Auto-resolution with enableAutoResolution=false leaves matching flow alert open', async () => {
    // Explicitly disable auto-resolution
    await request(app)
      .patch('/api/settings/enableAutoResolution')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({ value: false });

    const alertX = await Alert.create({
      timestamp: new Date(),
      severity: 'high',
      attackType: 'DoS',
      prediction: 'DoS',
      confidence: 0.95,
      datasetType: 'nsl_kdd',
      modelVersion: 'test-v1',
      status: 'open',
      description: 'Threat alert X',
      sourceInfo: { src_ip: '10.0.0.99', flow_id: 'FLOW-X' }
    });

    // Ingest benign flow with EXACT matching flow_id
    const resBenign = await request(app)
      .post('/api/predictions')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({
        datasetType: 'nsl_kdd',
        inputData: {
          duration: 0,
          protocol_type: 'tcp',
          service: 'http',
          flag: 'SF',
          src_bytes: 215,
          dst_bytes: 4500
        },
        sourceInfo: { src_ip: '10.0.0.99', flow_id: 'FLOW-X' }
      });

    expect(resBenign.statusCode).toEqual(200);

    const freshX = await Alert.findById(alertX._id);
    expect(freshX.status).toEqual('open');
    expect(freshX.resolvedAt).toBeNull();
  });

  test('Mandatory Security Test: distinct source ports with different flow_ids never collapse (Benign Flow C resolves neither Alert A nor B)', async () => {
    await request(app)
      .patch('/api/settings/enableAutoResolution')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({ value: true });

    // Alert A: src_ip, dst_ip, dst_port, protocol SAME, but src_port: 50001, flow_id: 'FLOW-A'
    const alertA = await Alert.create({
      timestamp: new Date(),
      severity: 'high',
      attackType: 'DoS',
      prediction: 'DoS',
      confidence: 0.95,
      datasetType: 'nsl_kdd',
      modelVersion: 'test-v1',
      status: 'open',
      description: 'Threat Alert A',
      sourceInfo: {
        src_ip: '192.168.10.50',
        dst_ip: '10.0.0.1',
        src_port: 50001,
        dst_port: 80,
        protocol: 'tcp',
        flow_id: 'FLOW-A'
      }
    });

    // Alert B: src_ip, dst_ip, dst_port, protocol SAME, but src_port: 50002, flow_id: 'FLOW-B'
    const alertB = await Alert.create({
      timestamp: new Date(),
      severity: 'high',
      attackType: 'DoS',
      prediction: 'DoS',
      confidence: 0.91,
      datasetType: 'nsl_kdd',
      modelVersion: 'test-v1',
      status: 'open',
      description: 'Threat Alert B',
      sourceInfo: {
        src_ip: '192.168.10.50',
        dst_ip: '10.0.0.1',
        src_port: 50002,
        dst_port: 80,
        protocol: 'tcp',
        flow_id: 'FLOW-B'
      }
    });

    // Benign Flow C: src_ip, dst_ip, dst_port, protocol SAME, but src_port: 50003, flow_id: 'FLOW-C'
    const resBenignC = await request(app)
      .post('/api/predictions')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({
        datasetType: 'nsl_kdd',
        inputData: { duration: 0, protocol_type: 'tcp', service: 'http', flag: 'SF', src_bytes: 215, dst_bytes: 4500 },
        sourceInfo: {
          src_ip: '192.168.10.50',
          dst_ip: '10.0.0.1',
          src_port: 50003,
          dst_port: 80,
          protocol: 'tcp',
          flow_id: 'FLOW-C'
        }
      });

    expect(resBenignC.statusCode).toEqual(200);

    // Verify Benign Flow C resolved NONE of Alert A or Alert B
    const freshA = await Alert.findById(alertA._id);
    const freshB = await Alert.findById(alertB._id);
    expect(freshA.status).toEqual('open');
    expect(freshA.resolvedAt).toBeNull();
    expect(freshB.status).toEqual('open');
    expect(freshB.resolvedAt).toBeNull();
  });

  test('Exact Match Test: Complete 5-tuple without flow_id resolves matching Alert A and leaves Alert B with different src_port open', async () => {
    await request(app)
      .patch('/api/settings/enableAutoResolution')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({ value: true });

    // Alert A with complete 5-tuple (src_port: 41001)
    const alertA = await Alert.create({
      timestamp: new Date(),
      severity: 'high',
      attackType: 'PortScan',
      prediction: 'PortScan',
      confidence: 0.94,
      datasetType: 'nsl_kdd',
      modelVersion: 'test-v1',
      status: 'open',
      description: 'Alert A 5-tuple',
      sourceInfo: {
        src_ip: '172.16.0.5',
        dst_ip: '10.0.0.10',
        src_port: 41001,
        dst_port: 443,
        protocol: 'tcp'
      }
    });

    // Alert B with different src_port (41002)
    const alertB = await Alert.create({
      timestamp: new Date(),
      severity: 'high',
      attackType: 'PortScan',
      prediction: 'PortScan',
      confidence: 0.92,
      datasetType: 'nsl_kdd',
      modelVersion: 'test-v1',
      status: 'open',
      description: 'Alert B 5-tuple',
      sourceInfo: {
        src_ip: '172.16.0.5',
        dst_ip: '10.0.0.10',
        src_port: 41002,
        dst_port: 443,
        protocol: 'tcp'
      }
    });

    // Submit benign flow matching EXACT complete 5-tuple of Alert A, with NO flow_id
    const resBenign = await request(app)
      .post('/api/predictions')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({
        datasetType: 'nsl_kdd',
        inputData: { duration: 0, protocol_type: 'tcp', service: 'https', flag: 'SF', src_bytes: 200, dst_bytes: 1500 },
        sourceInfo: {
          src_ip: '172.16.0.5',
          dst_ip: '10.0.0.10',
          src_port: 41001,
          dst_port: 443,
          protocol: 'tcp'
        }
      });

    expect(resBenign.statusCode).toEqual(200);

    // Verify Alert A IS resolved
    const freshA = await Alert.findById(alertA._id);
    expect(freshA.status).toEqual('resolved');
    expect(freshA.resolvedAt).not.toBeNull();
    expect(freshA.description).toContain('[Auto-resolved: benign traffic resumed for 5-tuple 172.16.0.5:41001->10.0.0.10:443(tcp)]');

    // Verify Alert B remains OPEN
    const freshB = await Alert.findById(alertB._id);
    expect(freshB.status).toEqual('open');
    expect(freshB.resolvedAt).toBeNull();
  });

  test('Partial-Tuple Safety Tests: Missing any 5-tuple component (src_port, protocol, etc.) strictly skips auto-resolution', async () => {
    await request(app)
      .patch('/api/settings/enableAutoResolution')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({ value: true });

    const alertTarget = await Alert.create({
      timestamp: new Date(),
      severity: 'high',
      attackType: 'DoS',
      prediction: 'DoS',
      confidence: 0.95,
      datasetType: 'nsl_kdd',
      modelVersion: 'test-v1',
      status: 'open',
      description: 'Target Alert',
      sourceInfo: {
        src_ip: '10.1.1.1',
        dst_ip: '10.2.2.2',
        src_port: 33333,
        dst_port: 8080,
        protocol: 'tcp'
      }
    });

    // Case 1: missing src_port (only src_ip + dst_ip + dst_port + protocol)
    await request(app)
      .post('/api/predictions')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({
        datasetType: 'nsl_kdd',
        inputData: { duration: 0, protocol_type: 'tcp', service: 'http', flag: 'SF' },
        sourceInfo: { src_ip: '10.1.1.1', dst_ip: '10.2.2.2', dst_port: 8080, protocol: 'tcp' }
      });
    expect((await Alert.findById(alertTarget._id)).status).toEqual('open');

    // Case 2: missing protocol (only src_ip + dst_ip + src_port + dst_port)
    await request(app)
      .post('/api/predictions')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({
        datasetType: 'nsl_kdd',
        inputData: { duration: 0, service: 'http', flag: 'SF' },
        sourceInfo: { src_ip: '10.1.1.1', dst_ip: '10.2.2.2', src_port: 33333, dst_port: 8080 }
      });
    expect((await Alert.findById(alertTarget._id)).status).toEqual('open');

    // Case 3: only src_ip + dst_ip + dst_port
    await request(app)
      .post('/api/predictions')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({
        datasetType: 'nsl_kdd',
        inputData: { duration: 0, service: 'http', flag: 'SF' },
        sourceInfo: { src_ip: '10.1.1.1', dst_ip: '10.2.2.2', dst_port: 8080 }
      });
    expect((await Alert.findById(alertTarget._id)).status).toEqual('open');

    // Case 4: only src_ip + dst_ip + protocol
    await request(app)
      .post('/api/predictions')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({
        datasetType: 'nsl_kdd',
        inputData: { duration: 0, protocol_type: 'tcp', service: 'http', flag: 'SF' },
        sourceInfo: { src_ip: '10.1.1.1', dst_ip: '10.2.2.2', protocol: 'tcp' }
      });
    expect((await Alert.findById(alertTarget._id)).status).toEqual('open');

    // Case 5: only src_ip
    await request(app)
      .post('/api/predictions')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({
        datasetType: 'nsl_kdd',
        inputData: { duration: 0, service: 'http', flag: 'SF' },
        sourceInfo: { src_ip: '10.1.1.1' }
      });
    expect((await Alert.findById(alertTarget._id)).status).toEqual('open');
  });
});
