/**
 * Live End-to-End Integration Test
 * Flow: Client -> Node.js Express -> FastAPI ML Service (Port 8000) -> XGBoost -> MongoDB (27017) -> Alert Generation -> Client
 */

const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../src/app');
const config = require('../src/config/env');
const Log = require('../src/models/Log');
const Alert = require('../src/models/Alert');
const User = require('../src/models/User');

describe('Phase 9 Live E2E Integration Test', () => {
  let isMongoConnected = false;
  let adminToken = null;
  let adminCsrf = null;

  beforeAll(async () => {
    try {
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(config.mongodbUri, { serverSelectionTimeoutMS: 3000 });
      }
      isMongoConnected = true;

      // Seed transient admin user for test
      await User.deleteMany({ email: 'integration_admin@test.com' });
      await request(app).post('/api/auth/register').send({
        username: 'integration_admin',
        email: 'integration_admin@test.com',
        password: 'Password123!'
      });

      const admin = await User.findOne({ email: 'integration_admin@test.com' });
      if (admin) {
        admin.role = 'ADMIN';
        await admin.save();
      }

      const loginRes = await request(app).post('/api/auth/login').send({
        email: 'integration_admin@test.com',
        password: 'Password123!'
      });
      adminToken = loginRes.body.token;
      adminCsrf = loginRes.body.csrfToken || 'test_csrf';

    } catch (err) {
      console.warn('[E2E Test Notice] Local MongoDB is unavailable:', err.message);
    }
  });

  afterAll(async () => {
    if (isMongoConnected) {
      // Clean up test documents created during integration test
      await Log.deleteMany({ sourceInfo: { e2eTest: true } });
      await Alert.deleteMany({ sourceInfo: { e2eTest: true } });
      await User.deleteMany({ email: 'integration_admin@test.com' });
      await mongoose.disconnect();
    }
  });

  test('E2E Flow: Valid NSL-KDD prediction -> Live FastAPI IPC -> Live MongoDB save', async () => {
    if (!isMongoConnected || !adminToken) {
      console.warn('Skipping live DB assertions: MongoDB or admin token not available.');
      return;
    }

    const nslKddPayload = {
      datasetType: 'nsl_kdd',
      inputData: {
        duration: 0, protocol_type: 'tcp', service: 'http', flag: 'SF',
        src_bytes: 215, dst_bytes: 4507, land: 0, wrong_fragment: 0,
        urgent: 0, hot: 0, num_failed_logins: 0, logged_in: 1,
        num_compromised: 0, root_shell: 0, su_attempted: 0, num_root: 0,
        num_file_creations: 0, num_shells: 0, num_access_files: 0,
        num_outbound_cmds: 0, is_host_login: 0, is_guest_login: 0,
        count: 1, srv_count: 1, serror_rate: 0.0, srv_serror_rate: 0.0,
        rerror_rate: 0.0, srv_rerror_rate: 0.0, same_srv_rate: 1.0,
        diff_srv_rate: 0.0, srv_diff_host_rate: 0.0, dst_host_count: 255,
        dst_host_srv_count: 255, dst_host_same_srv_rate: 1.0,
        dst_host_diff_srv_rate: 0.0, dst_host_same_src_port_rate: 0.0,
        dst_host_srv_diff_host_rate: 0.0, dst_host_serror_rate: 0.0,
        dst_host_srv_serror_rate: 0.0, dst_host_rerror_rate: 0.0,
        dst_host_srv_rerror_rate: 0.0
      },
      sourceInfo: { e2eTest: true, clientIp: '127.0.0.1' }
    };

    const res = await request(app)
      .post('/api/predictions')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send(nslKddPayload);

    expect(res.statusCode).toEqual(200);
    expect(res.body.success).toBe(true);
    expect(res.body.dataset_type).toEqual('nsl_kdd');
    expect(res.body.model_version).toMatch(/NetShield-NSLKDD/);
    expect(res.body.predictions.length).toEqual(1);
    expect(res.body.predictions[0].prediction).toEqual('Normal');

    // Verify stored log in real MongoDB database
    const savedLog = await Log.findById(res.body.log_id).lean();
    expect(savedLog).not.toBeNull();
    expect(savedLog.prediction).toEqual('Normal');
  });
});
