const request = require('supertest');
const app = require('../src/app');
const mlService = require('../src/services/mlService');

jest.mock('../src/services/mlService');

describe('Health API Endpoints', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('GET /health returns HTTP 200 with healthy status when ML service is online', async () => {
    mlService.checkHealth.mockResolvedValueOnce({ status: 'healthy' });

    const res = await request(app).get('/health');
    expect(res.statusCode).toEqual(200);
    expect(res.body).toHaveProperty('status');
    expect(res.body).toHaveProperty('service', 'NetShield Node.js Backend');
    expect(res.body).toHaveProperty('services');
    expect(res.body.services).toHaveProperty('mongodb');
    expect(res.body.services).toHaveProperty('mlService');
  });

  test('GET /api/health returns HTTP 200 with degraded status when ML service is offline', async () => {
    mlService.checkHealth.mockResolvedValueOnce({ status: 'unavailable' });

    const res = await request(app).get('/api/health');
    expect(res.statusCode).toEqual(200);
    expect(res.body.status).toEqual('degraded');
  });

  test('GET /unknown-route returns HTTP 404', async () => {
    const res = await request(app).get('/unknown-route');
    expect(res.statusCode).toEqual(404);
    expect(res.body.error.message).toContain('Resource not found');
  });
});
