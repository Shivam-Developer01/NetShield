const http = require('http');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const request = require('supertest');
const { io: Client } = require('socket.io-client');
const app = require('../src/app');
const User = require('../src/models/User');
const Log = require('../src/models/Log');
const Alert = require('../src/models/Alert');
const { initSocketServer, closeSocketServer } = require('../src/realtime/socketServer');
const mlService = require('../src/services/mlService');

jest.mock('../src/services/mlService', () => ({
  checkHealth: jest.fn(),
  getHealth: jest.fn(),
  getModelInfo: jest.fn(),
  predict: jest.fn()
}));

jest.setTimeout(30000);

let mongoServer;
let httpServer;
let serverPort;
let adminCookie, analystCookie, viewerCookie;
let adminCsrf, analystCsrf, viewerCsrf;
let adminToken, analystToken, viewerToken;
let adminUser, analystUser, viewerUser;

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  await mongoose.connect(mongoServer.getUri());

  httpServer = http.createServer(app);
  initSocketServer(httpServer);

  await new Promise((resolve) => {
    httpServer.listen(0, () => {
      serverPort = httpServer.address().port;
      resolve();
    });
  });
});

afterAll(async () => {
  await closeSocketServer();
  await new Promise((resolve) => httpServer.close(resolve));
  await mongoose.disconnect();
  await mongoServer.stop();
});

beforeEach(async () => {
  await User.deleteMany({});
  await Log.deleteMany({});
  await Alert.deleteMany({});
  jest.clearAllMocks();

  mlService.predict.mockImplementation(() => Promise.resolve({
    dataset_type: 'nsl_kdd',
    model_version: 'NetShield-NSLKDD-XGBoost-v1.0',
    records_processed: 1,
    client_latency_ms: 10,
    predictions: [{ record_index: 0, prediction: 'Normal', prediction_index: 1, confidence: 0.98, class_probabilities: { Normal: 0.98 } }]
  }));

  const getCookieString = (res) => {
    const cookies = res.headers['set-cookie'] || [];
    const tokenMatch = cookies.find(c => c.startsWith('netshield_token='));
    const tokenStr = tokenMatch ? tokenMatch.split(';')[0] : '';
    const xsrfStr = `XSRF-TOKEN=${res.body.csrfToken}`;
    return `${tokenStr}; ${xsrfStr}`;
  };

  // Register Admin & elevate role to ADMIN in DB
  await request(app).post('/api/auth/register').send({
    username: 'admin_sock',
    email: 'admin@socket.com',
    password: 'AdminPassword123!'
  });
  adminUser = await User.findOneAndUpdate({ email: 'admin@socket.com' }, { role: 'ADMIN' }, { new: true });

  const adminLogin = await request(app).post('/api/auth/login').send({
    email: 'admin@socket.com',
    password: 'AdminPassword123!'
  });
  adminCookie = getCookieString(adminLogin);
  adminToken = adminLogin.body.token;
  adminCsrf = adminLogin.body.csrfToken;

  // Register Analyst & elevate role to ANALYST in DB
  await request(app).post('/api/auth/register').send({
    username: 'analyst_sock',
    email: 'analyst@socket.com',
    password: 'AnalystPassword123!'
  });
  analystUser = await User.findOneAndUpdate({ email: 'analyst@socket.com' }, { role: 'ANALYST' }, { new: true });

  const analystLogin = await request(app).post('/api/auth/login').send({
    email: 'analyst@socket.com',
    password: 'AnalystPassword123!'
  });
  analystCookie = getCookieString(analystLogin);
  analystToken = analystLogin.body.token;
  analystCsrf = analystLogin.body.csrfToken;

  // Register Viewer
  const viewerRes = await request(app).post('/api/auth/register').send({
    username: 'viewer_sock',
    email: 'viewer@socket.com',
    password: 'ViewerPassword123!',
    role: 'VIEWER'
  });
  viewerUser = viewerRes.body.user;

  const viewerLogin = await request(app).post('/api/auth/login').send({
    email: 'viewer@socket.com',
    password: 'ViewerPassword123!'
  });
  viewerCookie = getCookieString(viewerLogin);
  viewerToken = viewerLogin.body.token;
  viewerCsrf = viewerLogin.body.csrfToken;
});

function createClient(cookieHeader) {
  const cookieStr = Array.isArray(cookieHeader)
    ? cookieHeader.map(c => c.split(';')[0]).join('; ')
    : (cookieHeader || '');
  return Client(`http://localhost:${serverPort}`, {
    extraHeaders: {
      cookie: cookieStr
    },
    transports: ['websocket'],
    reconnection: false
  });
}

describe('Phase 14 — Socket.IO Real-Time Authentication & RBAC Suite', () => {

  test('1. ADMIN can connect to Socket.IO', (done) => {
    const client = createClient(adminCookie);
    client.on('connect', () => {
      expect(client.connected).toBe(true);
      client.disconnect();
      done();
    });
  });

  test('2. ANALYST can connect to Socket.IO', (done) => {
    const client = createClient(analystCookie);
    client.on('connect', () => {
      expect(client.connected).toBe(true);
      client.disconnect();
      done();
    });
  });

  test('3. VIEWER can connect to Socket.IO', (done) => {
    const client = createClient(viewerCookie);
    client.on('connect', () => {
      expect(client.connected).toBe(true);
      client.disconnect();
      done();
    });
  });

  test('4. Unauthenticated socket connection is rejected', (done) => {
    const client = createClient('');
    client.on('connect_error', (err) => {
      expect(err.message).toContain('Authentication error');
      client.disconnect();
      done();
    });
  });

  test('5. Invalid JWT token socket connection is rejected', (done) => {
    const client = createClient('netshield_token=invalid.jwt.token');
    client.on('connect_error', (err) => {
      expect(err.message).toContain('Authentication error');
      client.disconnect();
      done();
    });
  });

  test('6. Inactive user socket connection is rejected', async () => {
    const userId = viewerUser._id || viewerUser.id;
    await User.findByIdAndUpdate(userId, { isActive: false });
    const client = createClient(viewerCookie);

    await new Promise((resolve) => {
      client.on('connect_error', (err) => {
        expect(err.message).toContain('Authentication error');
        client.disconnect();
        resolve();
      });
    });
  }, 10000);

  test('7. VIEWER cannot arbitrarily join privileged rooms', (done) => {
    const client = createClient(viewerCookie);
    client.on('connect', () => {
      client.emit('join_room', 'soc:admins');
    });

    client.on('error', (err) => {
      expect(err.message).toContain('Forbidden');
      client.disconnect();
      done();
    });
  });

  test('8. Prediction event is published after POST /api/predictions', async () => {
    const analystClient = createClient(analystCookie);

    await new Promise((resolve) => {
      analystClient.on('connect', resolve);
    });

    const eventPromise = new Promise((resolve) => {
      analystClient.on('prediction.created', (envelope) => {
        expect(envelope.event).toBe('prediction.created');
        expect(envelope.data.prediction).toBe('Normal');
        expect(envelope.requestId).toBeDefined();
        resolve();
      });
    });

    const res = await request(app)
      .post('/api/predictions')
      .set('Authorization', `Bearer ${analystToken}`)
      .set('Cookie', analystCookie)
      .set('X-XSRF-TOKEN', analystCsrf)
      .send({
        datasetType: 'nsl_kdd',
        inputData: { duration: 0, protocol_type: 'tcp', service: 'http', flag: 'SF' }
      });

    expect(res.statusCode).toBe(200);

    await eventPromise;
    analystClient.disconnect();
  });

  test('9. Malicious prediction triggers alert.created to VIEWER and ANALYST', async () => {
    mlService.predict.mockImplementationOnce(() => Promise.resolve({
      dataset_type: 'nsl_kdd',
      model_version: 'NetShield-NSLKDD-XGBoost-v1.0',
      records_processed: 1,
      client_latency_ms: 15,
      predictions: [{ record_index: 0, prediction: 'neptune', prediction_index: 0, confidence: 0.99, class_probabilities: { neptune: 0.99 } }]
    }));

    const viewerClient = createClient(viewerCookie);
    await new Promise((resolve) => viewerClient.on('connect', resolve));

    const alertEventPromise = new Promise((resolve) => {
      viewerClient.on('alert.created', (envelope) => {
        expect(envelope.event).toBe('alert.created');
        expect(envelope.data.prediction).toBe('neptune');
        expect(envelope.data.severity).toBe('medium');
        expect(envelope.requestId).toBeDefined();
        resolve();
      });
    });

    await request(app)
      .post('/api/predictions')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', adminCookie)
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({
        datasetType: 'nsl_kdd',
        inputData: { duration: 0, protocol_type: 'tcp', service: 'private', flag: 'REJ' }
      })
      .expect(200);

    await alertEventPromise;
    viewerClient.disconnect();
  });

  test('10. Alert status update triggers alert.updated event', async () => {
    const alert = new Alert({
      timestamp: new Date(),
      severity: 'high',
      attackType: 'DoS',
      prediction: 'neptune',
      confidence: 0.99,
      datasetType: 'nsl_kdd',
      modelVersion: 'v1.0',
      status: 'open',
      description: 'Neptune DoS Attack Detected'
    });
    await alert.save();

    const viewerClient = createClient(viewerCookie);
    await new Promise((resolve) => viewerClient.on('connect', resolve));

    const updateEventPromise = new Promise((resolve) => {
      viewerClient.on('alert.updated', (envelope) => {
        expect(envelope.event).toBe('alert.updated');
        expect(envelope.data.status).toBe('acknowledged');
        expect(envelope.data.previousStatus).toBe('open');
        expect(envelope.requestId).toBeDefined();
        resolve();
      });
    });

    await request(app)
      .patch(`/api/alerts/${alert._id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', adminCookie)
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({ status: 'acknowledged' })
      .expect(200);

    await updateEventPromise;
    viewerClient.disconnect();
  });

  test('11. Secret keys are automatically redacted from event envelopes', async () => {
    const { createEnvelope } = require('../src/realtime/eventPublisher');
    const secretData = {
      prediction: 'Normal',
      password: 'SuperSecretPassword',
      passwordHash: 'hashed123',
      token: 'jwt.token.string',
      csrfToken: 'csrf123'
    };

    const envelope = createEnvelope('prediction.created', secretData, 'req-test');
    expect(envelope.data.prediction).toBe('Normal');
    expect(envelope.data.password).toBeUndefined();
    expect(envelope.data.passwordHash).toBeUndefined();
    expect(envelope.data.token).toBeUndefined();
    expect(envelope.data.csrfToken).toBeUndefined();
  });

});
