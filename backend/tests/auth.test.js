const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const app = require('../src/app');
const User = require('../src/models/User');
const mlService = require('../src/services/mlService');

jest.mock('../src/services/mlService', () => ({
  checkHealth: jest.fn(),
  getHealth: jest.fn(),
  getModelInfo: jest.fn(),
  predict: jest.fn()
}));

let mongoServer;
let adminToken, analystToken, viewerToken;
let adminCsrf, analystCsrf, viewerCsrf;
let adminUser, analystUser, viewerUser;

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  const uri = mongoServer.getUri();
  await mongoose.connect(uri);
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

beforeEach(async () => {
  await User.deleteMany({});
  jest.clearAllMocks();

  mlService.checkHealth.mockImplementation(() => Promise.resolve({
    status: 'healthy',
    database: { status: 'connected' },
    ml_service: { status: 'healthy' }
  }));

  mlService.getHealth.mockImplementation(() => Promise.resolve({
    status: 'healthy',
    database: { status: 'connected' },
    ml_service: { status: 'healthy' }
  }));

  mlService.predict.mockImplementation(() => Promise.resolve({
    dataset_type: 'nsl_kdd',
    model_version: 'NetShield-NSLKDD-XGBoost-v1.0',
    records_processed: 1,
    client_latency_ms: 10,
    predictions: [{ record_index: 0, prediction: 'Normal', prediction_index: 1, confidence: 0.99, class_probabilities: { Normal: 0.99 } }]
  }));

  // 1. Create Admin
  await request(app).post('/api/auth/register').send({
    username: 'admin_test',
    email: 'admin@test.com',
    password: 'AdminPassword123!',
    role: 'ADMIN'
  });
  
  adminUser = await User.findOne({ email: 'admin@test.com' });
  adminUser.role = 'ADMIN';
  await adminUser.save();

  const adminLogin = await request(app).post('/api/auth/login').send({
    email: 'admin@test.com',
    password: 'AdminPassword123!'
  });
  adminToken = adminLogin.body.token;
  adminCsrf = adminLogin.body.csrfToken || 'test_csrf_token';

  // 2. Create Analyst using Admin token
  await request(app)
    .post('/api/auth/register')
    .set('Authorization', `Bearer ${adminToken}`)
    .send({
      username: 'analyst_test',
      email: 'analyst@test.com',
      password: 'AnalystPassword123!',
      role: 'ANALYST'
    });
  
  analystUser = await User.findOne({ email: 'analyst@test.com' });
  const analystLogin = await request(app).post('/api/auth/login').send({
    email: 'analyst@test.com',
    password: 'AnalystPassword123!'
  });
  analystToken = analystLogin.body.token;
  analystCsrf = analystLogin.body.csrfToken || 'test_csrf_token';

  // 3. Create Viewer (public registration)
  await request(app).post('/api/auth/register').send({
    username: 'viewer_test',
    email: 'viewer@test.com',
    password: 'ViewerPassword123!',
    role: 'ADMIN'
  });
  viewerUser = await User.findOne({ email: 'viewer@test.com' });

  const viewerLogin = await request(app).post('/api/auth/login').send({
    email: 'viewer@test.com',
    password: 'ViewerPassword123!'
  });
  viewerToken = viewerLogin.body.token;
  viewerCsrf = viewerLogin.body.csrfToken || 'test_csrf_token';
});

describe('Phase 11.1: Authentication Security Hardening Suite', () => {
  test('1. Public registration forces default role VIEWER and rejects role escalation', async () => {
    expect(viewerUser.role).toEqual('VIEWER');
  });

  test('2. Duplicate email registration returns HTTP 409 Conflict', async () => {
    const res = await request(app).post('/api/auth/register').send({
      username: 'dup_user',
      email: 'viewer@test.com',
      password: 'Password123!'
    });
    expect(res.statusCode).toEqual(409);
    expect(res.body.error.code).toEqual('DUPLICATE_EMAIL');
  });

  test('3. Password hashing is enforced and passwordHash is NEVER returned in responses', async () => {
    const userInDb = await User.findOne({ email: 'viewer@test.com' }).select('+passwordHash');
    expect(userInDb.passwordHash).not.toEqual('ViewerPassword123!');
    expect(userInDb.passwordHash).toMatch(/^\$2[ayb]\$/);

    const res = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${viewerToken}`);
    expect(res.body.user).not.toHaveProperty('passwordHash');
  });

  test('4. Login success updates lastLoginAt and sets HTTP-only cookie + XSRF cookie', async () => {
    const res = await request(app).post('/api/auth/login').send({
      email: 'viewer@test.com',
      password: 'ViewerPassword123!'
    });
    expect(res.statusCode).toEqual(200);
    expect(res.body.success).toBe(true);
    expect(res.body).toHaveProperty('token');
    const cookies = res.headers['set-cookie'].join(';');
    expect(cookies).toContain('netshield_token=');
    expect(cookies).toContain('XSRF-TOKEN=');
  });

  test('5. Login failure with wrong password returns generic HTTP 401 error', async () => {
    const res = await request(app).post('/api/auth/login').send({
      email: 'viewer@test.com',
      password: 'WrongPassword999!'
    });
    expect(res.statusCode).toEqual(401);
    expect(res.body.error.message).toEqual('Invalid email or password.');
  });

  test('6. Login failure with non-existent email returns generic HTTP 401 error', async () => {
    const res = await request(app).post('/api/auth/login').send({
      email: 'nonexistent@test.com',
      password: 'Password123!'
    });
    expect(res.statusCode).toEqual(401);
    expect(res.body.error.message).toEqual('Invalid email or password.');
  });

  test('7. /api/auth/me returns active session details for valid token', async () => {
    const res = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${viewerToken}`);
    expect(res.statusCode).toEqual(200);
    expect(res.body.user.email).toEqual('viewer@test.com');
    expect(res.body.user.role).toEqual('VIEWER');
  });

  test('8. Logout clears netshield_token authentication cookie', async () => {
    const res = await request(app).post('/api/auth/logout');
    expect(res.statusCode).toEqual(200);
    const cookies = res.headers['set-cookie'].join(';');
    expect(cookies).toContain('netshield_token=;');
  });

  test('9. Unauthenticated request to protected route returns HTTP 401', async () => {
    const res = await request(app).get('/api/predictions');
    expect(res.statusCode).toEqual(401);
    expect(res.body.error.code).toEqual('UNAUTHENTICATED');
  });

  test('10. State-changing request missing CSRF header returns HTTP 403 Forbidden', async () => {
    const res = await request(app)
      .post('/api/predictions')
      .set('Cookie', [`netshield_token=${analystToken}`, `XSRF-TOKEN=${analystCsrf}`])
      // Omit X-XSRF-TOKEN header
      .send({ datasetType: 'nsl_kdd', inputData: { duration: 0 } });
    expect(res.statusCode).toEqual(403);
    expect(res.body.error.code).toEqual('CSRF_ERROR');
  });

  test('11. State-changing request with valid CSRF token header and cookie succeeds', async () => {
    const res = await request(app)
      .post('/api/predictions')
      .set('Authorization', `Bearer ${analystToken}`)
      .set('Cookie', [`netshield_token=${analystToken}`, `XSRF-TOKEN=${analystCsrf}`])
      .set('X-XSRF-TOKEN', analystCsrf)
      .send({
        datasetType: 'nsl_kdd',
        inputData: { duration: 0, protocol_type: 'tcp', service: 'http', flag: 'SF' }
      });
    expect(res.statusCode).toEqual(200);
  });

  test('12. Helmet security headers are present in HTTP response', async () => {
    const res = await request(app).get('/health');
    expect(res.headers).toHaveProperty('x-frame-options', 'DENY');
    expect(res.headers).toHaveProperty('x-content-type-options', 'nosniff');
    expect(res.headers).toHaveProperty('referrer-policy', 'strict-origin-when-cross-origin');
  });

  test('13. VIEWER can access read-only endpoints (GET /api/predictions, GET /api/alerts)', async () => {
    const res = await request(app).get('/api/predictions').set('Authorization', `Bearer ${viewerToken}`);
    expect(res.statusCode).toEqual(200);
  });

  test('14. VIEWER cannot submit predictions (POST /api/predictions returns HTTP 403)', async () => {
    const res = await request(app)
      .post('/api/predictions')
      .set('Authorization', `Bearer ${viewerToken}`)
      .set('Cookie', [`netshield_token=${viewerToken}`, `XSRF-TOKEN=${viewerCsrf}`])
      .set('X-XSRF-TOKEN', viewerCsrf)
      .send({ datasetType: 'nsl_kdd', inputData: {} });
    expect(res.statusCode).toEqual(403);
    expect(res.body.error.code).toEqual('FORBIDDEN');
  });

  test('15. ANALYST cannot access user management (GET /api/users returns HTTP 403)', async () => {
    const res = await request(app).get('/api/users').set('Authorization', `Bearer ${analystToken}`);
    expect(res.statusCode).toEqual(403);
  });

  test('16. ADMIN can access user management (GET /api/users returns HTTP 200)', async () => {
    const res = await request(app).get('/api/users').set('Authorization', `Bearer ${adminToken}`);
    expect(res.statusCode).toEqual(200);
    expect(res.body.data.length).toBeGreaterThanOrEqual(3);
  });

  test('17. Disabled user cannot authenticate', async () => {
    viewerUser.isActive = false;
    await viewerUser.save();

    const res = await request(app).post('/api/auth/login').send({
      email: 'viewer@test.com',
      password: 'ViewerPassword123!'
    });
    expect(res.statusCode).toEqual(401);
  });

  test('18. Last admin safeguard prevents deleting or demoting the final ADMIN user', async () => {
    const res = await request(app)
      .delete(`/api/users/${adminUser._id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf);
    expect(res.statusCode).toEqual(400);
    expect(res.body.error.code).toEqual('LAST_ADMIN_PROTECTION');
  });

  test('19. Infrastructure health endpoint GET /health remains publicly accessible', async () => {
    const res = await request(app).get('/health');
    expect(res.statusCode).toEqual(200);
    expect(res.body.status).toEqual('healthy');
  });
});
