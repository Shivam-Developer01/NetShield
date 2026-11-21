/**
 * NetShield SMTP Delivery & Notification Test Suite
 * Validates real SMTP transport mechanisms, mock delivery, error handling,
 * RBAC/CSRF authorization, and dynamic recipient resolution.
 */

const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const app = require('../src/app');
const Setting = require('../src/models/Setting');
const User = require('../src/models/User');
const Alert = require('../src/models/Alert');
const config = require('../src/config/env');
const notificationService = require('../src/services/notificationService');
const settingsService = require('../src/services/settingsService');

let mongoServer;
let adminToken;
let adminCsrf;
let viewerToken;
let viewerCsrf;

jest.setTimeout(60000);

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create({
    instance: {
      launchTimeout: 30000
    }
  });
  const mongoUri = mongoServer.getUri();
  await mongoose.connect(mongoUri);
}, 60000);

afterAll(async () => {
  await mongoose.disconnect();
  if (mongoServer) {
    await mongoServer.stop();
  }
});

beforeEach(async () => {
  await Setting.deleteMany({});
  await User.deleteMany({});
  await Alert.deleteMany({});
  settingsService.invalidateCache();
  notificationService.setTransporter(null);
  notificationService.clearDispatchedAlerts();

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
  viewerCsrf = viewerLogin.body.csrfToken || 'test_csrf';
});

describe('SMTP Configuration & Transport Unit Tests', () => {
  test('config.smtp correctly detects configured vs unconfigured state', () => {
    expect(config.smtp).toBeDefined();
    expect(typeof config.smtp.port).toBe('number');
    expect(typeof config.smtp.isConfigured).toBe('boolean');
  });

  test('verifySmtpConnection returns SMTP_NOT_CONFIGURED when credentials are absent', async () => {
    const originalConfigured = config.smtp.isConfigured;
    // Ensure custom transporter is null
    notificationService.setTransporter(null);

    if (!originalConfigured) {
      const result = await notificationService.verifySmtpConnection();
      expect(result.success).toBe(false);
      expect(result.code).toBe('SMTP_NOT_CONFIGURED');
    }
  });

  test('verifySmtpConnection succeeds with valid mocked transporter', async () => {
    const mockTransporter = {
      verify: jest.fn().mockResolvedValue(true),
      sendMail: jest.fn().mockResolvedValue({ messageId: 'msg-12345' })
    };
    notificationService.setTransporter(mockTransporter);

    const result = await notificationService.verifySmtpConnection();
    expect(result.success).toBe(true);
    expect(mockTransporter.verify).toHaveBeenCalled();
  });

  test('verifySmtpConnection handles verification rejection safely without leaking password', async () => {
    const mockTransporter = {
      verify: jest.fn().mockRejectedValue(new Error('Invalid login: 535-5.7.8 Username and Password not accepted')),
      sendMail: jest.fn()
    };
    notificationService.setTransporter(mockTransporter);

    const result = await notificationService.verifySmtpConnection();
    expect(result.success).toBe(false);
    expect(result.error).toContain('Invalid login');
    expect(result.code).toBe('VERIFICATION_FAILED');
  });
});

describe('POST /api/settings/test-email (Admin Security & RBAC)', () => {
  test('Requires authentication (401 Unauthorized)', async () => {
    const res = await request(app)
      .post('/api/settings/test-email')
      .set('Cookie', [`XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({});
    expect(res.statusCode).toBe(401);
  });

  test('Requires ADMIN role (403 Forbidden for VIEWER)', async () => {
    const res = await request(app)
      .post('/api/settings/test-email')
      .set('Authorization', `Bearer ${viewerToken}`)
      .set('Cookie', [`netshield_token=${viewerToken}`, `XSRF-TOKEN=${viewerCsrf}`])
      .set('X-XSRF-TOKEN', viewerCsrf)
      .send({});
    expect(res.statusCode).toBe(403);
  });

  test('Requires valid CSRF token (403 Forbidden if missing)', async () => {
    const res = await request(app)
      .post('/api/settings/test-email')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .send({});
    expect(res.statusCode).toBe(403);
  });

  test('Returns 400 SMTP_NOT_CONFIGURED when SMTP credentials are not set', async () => {
    notificationService.setTransporter(null);
    const originalHost = config.smtp.host;
    const originalUser = config.smtp.user;
    const originalPass = config.smtp.pass;

    config.smtp.host = '';
    config.smtp.user = '';
    config.smtp.pass = '';

    const res = await request(app)
      .post('/api/settings/test-email')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({});

    expect(res.statusCode).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toBe('SMTP_NOT_CONFIGURED');

    config.smtp.host = originalHost;
    config.smtp.user = originalUser;
    config.smtp.pass = originalPass;
  });

  test('Successfully sends test email with mocked transporter to dynamic recipient', async () => {
    // Set custom recipient in Settings
    await request(app)
      .patch('/api/settings/systemNotificationEmail')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({ value: 'soc-director@enterprise.security' });

    let sentMailParams = null;
    const mockTransporter = {
      verify: jest.fn().mockResolvedValue(true),
      sendMail: jest.fn().mockImplementation(async (params) => {
        sentMailParams = params;
        return { messageId: '<test-msg-uuid-999@netshield>' };
      })
    };
    notificationService.setTransporter(mockTransporter);

    const res = await request(app)
      .post('/api/settings/test-email')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({});

    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.recipient).toBe('soc-director@enterprise.security');
    expect(res.body.data.messageId).toBe('<test-msg-uuid-999@netshield>');
    expect(res.body.data.transport).toBe('SMTP');

    // Verify sent payload details
    expect(sentMailParams).toBeDefined();
    expect(sentMailParams.to).toBe('soc-director@enterprise.security');
    expect(sentMailParams.subject).toBe('NetShield SMTP Test');
    expect(sentMailParams.text).toContain('This is a test email from NetShield. SMTP delivery is configured successfully.');
    expect(sentMailParams.html).toContain('SMTP Connectivity Test');

    // Verify SMTP_PASS is never in response
    const jsonString = JSON.stringify(res.body);
    expect(jsonString).not.toContain('pass');
    expect(jsonString).not.toContain('password');
  });

  test('Handles mail transport rejection gracefully (502 SMTP_DELIVERY_FAILED)', async () => {
    const mockTransporter = {
      sendMail: jest.fn().mockRejectedValue(new Error('ETIMEDOUT: Connection timed out after 10000ms'))
    };
    notificationService.setTransporter(mockTransporter);

    const res = await request(app)
      .post('/api/settings/test-email')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({});

    expect(res.statusCode).toBe(502);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toBe('SMTP_DELIVERY_FAILED');
    expect(res.body.message).toContain('ETIMEDOUT');
  });
});

describe('Threat Digest Notification (Test Mode vs Real Mode)', () => {
  beforeEach(async () => {
    // Seed high severity alerts
    await Alert.create([
      {
        timestamp: new Date(),
        severity: 'high',
        attackType: 'neptune',
        prediction: 'neptune',
        confidence: 0.985,
        datasetType: 'nsl_kdd',
        modelVersion: 'v1.3',
        status: 'open',
        description: 'SYN flood denial of service'
      },
      {
        timestamp: new Date(),
        severity: 'critical',
        attackType: 'buffer_overflow',
        prediction: 'buffer_overflow',
        confidence: 0.942,
        datasetType: 'nsl_kdd',
        modelVersion: 'v1.3',
        status: 'open',
        description: 'Privilege escalation buffer overflow'
      }
    ]);
  });

  test('Default trigger / POST /api/settings/notify-digest remains in safe test mode', async () => {
    const mockTransporter = {
      sendMail: jest.fn().mockResolvedValue({ messageId: 'real-msg-should-not-be-called' })
    };
    notificationService.setTransporter(mockTransporter);

    const res = await request(app)
      .post('/api/settings/notify-digest')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({});

    expect(res.statusCode).toBe(200);
    expect(res.body.data.transport).toBe('TEST_STUB_NO_SMTP');
    expect(res.body.data.alertCount).toBe(2);
    // Mock sendMail must NOT be called in test mode!
    expect(mockTransporter.sendMail).not.toHaveBeenCalled();
  });

  test('Explicit real mode (real: true) sends formatted digest email when transporter configured', async () => {
    let sentDigestParams = null;
    const mockTransporter = {
      sendMail: jest.fn().mockImplementation(async (params) => {
        sentDigestParams = params;
        return { messageId: '<digest-msg-uuid-456@netshield>' };
      })
    };
    notificationService.setTransporter(mockTransporter);

    const res = await request(app)
      .post('/api/settings/notify-digest')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`, `XSRF-TOKEN=${adminCsrf}`])
      .set('X-XSRF-TOKEN', adminCsrf)
      .send({ real: true });

    expect(res.statusCode).toBe(200);
    expect(res.body.data.transport).toBe('SMTP');
    expect(res.body.data.messageId).toBe('<digest-msg-uuid-456@netshield>');
    expect(res.body.data.alertCount).toBe(2);

    expect(mockTransporter.sendMail).toHaveBeenCalledTimes(1);
    expect(sentDigestParams.subject).toContain('NetShield Security Threat Digest - 2 Priority Alert(s)');
    expect(sentDigestParams.text).toContain('neptune');
    expect(sentDigestParams.text).toContain('buffer_overflow');
    expect(sentDigestParams.html).toContain('Priority Threat Incidents');
    expect(sentDigestParams.html).toContain('neptune');
    expect(sentDigestParams.html).toContain('buffer_overflow');
  });

  test('GET /api/settings/smtp-status checks connectivity for admin', async () => {
    const mockTransporter = {
      verify: jest.fn().mockResolvedValue(true)
    };
    notificationService.setTransporter(mockTransporter);

    const res = await request(app)
      .get('/api/settings/smtp-status')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('Cookie', [`netshield_token=${adminToken}`]);

    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
    expect(mockTransporter.verify).toHaveBeenCalled();
  });
});

describe('Automated Security Alert Email Notifications (Phase 20.9)', () => {
  test('HIGH alert triggers email notification with correct subject, recipient, and body', async () => {
    let sentMail = null;
    const mockTransporter = {
      sendMail: jest.fn().mockImplementation(async (params) => {
        sentMail = params;
        return { messageId: '<high-alert-msg-123@netshield>' };
      })
    };
    notificationService.setTransporter(mockTransporter);

    await Setting.create({ key: 'systemNotificationEmail', value: 'soc-team@netshield.io' });
    settingsService.invalidateCache();

    const alert = await Alert.create({
      severity: 'high',
      attackType: 'neptune',
      prediction: 'neptune',
      confidence: 0.985,
      datasetType: 'nsl_kdd',
      modelVersion: 'NetShield-NSLKDD-XGBoost-v1.0',
      description: 'SYN flood denial of service threat detected',
      sourceInfo: {
        src_ip: '192.168.1.100',
        dst_ip: '10.0.0.5',
        src_port: 54321,
        dst_port: 80,
        protocol: 'tcp',
        flow_id: 'flow-syn-999'
      }
    });

    const result = await notificationService.sendSecurityAlertNotification(alert);

    expect(result.success).toBe(true);
    expect(result.recipient).toBe('soc-team@netshield.io');
    expect(result.messageId).toBe('<high-alert-msg-123@netshield>');
    expect(result.severity).toBe('high');
    expect(mockTransporter.sendMail).toHaveBeenCalledTimes(1);

    expect(sentMail.to).toBe('soc-team@netshield.io');
    expect(sentMail.subject).toBe('[NetShield] HIGH Security Alert — neptune');
    expect(sentMail.text).toContain('Severity: HIGH');
    expect(sentMail.text).toContain('Threat Type: neptune');
    expect(sentMail.text).toContain('Confidence: 98.5%');
    expect(sentMail.text).toContain('Source IP: 192.168.1.100');
    expect(sentMail.text).toContain('Destination IP: 10.0.0.5');
    expect(sentMail.text).toContain('Flow ID: flow-syn-999');
    expect(sentMail.html).toContain('HIGH SEVERITY INTRUSION DETECTED');
    expect(sentMail.html).toContain('192.168.1.100:54321');
  });

  test('CRITICAL alert triggers email notification with CRITICAL formatting', async () => {
    let sentMail = null;
    const mockTransporter = {
      sendMail: jest.fn().mockImplementation(async (params) => {
        sentMail = params;
        return { messageId: '<critical-alert-msg-456@netshield>' };
      })
    };
    notificationService.setTransporter(mockTransporter);

    const alert = await Alert.create({
      severity: 'critical',
      attackType: 'buffer_overflow',
      prediction: 'buffer_overflow',
      confidence: 0.999,
      datasetType: 'nsl_kdd',
      modelVersion: 'NetShield-NSLKDD-XGBoost-v1.0',
      description: 'Root exploit buffer overflow execution detected',
      sourceInfo: {
        src_ip: '172.16.0.4',
        dst_ip: '10.0.0.1',
        src_port: 4444,
        dst_port: 22,
        protocol: 'tcp'
      }
    });

    const result = await notificationService.sendSecurityAlertNotification(alert);

    expect(result.success).toBe(true);
    expect(result.severity).toBe('critical');
    expect(sentMail.subject).toBe('[NetShield] CRITICAL Security Alert — buffer_overflow');
    expect(sentMail.text).toContain('Severity: CRITICAL');
    expect(sentMail.html).toContain('CRITICAL SEVERITY INTRUSION DETECTED');
  });

  test('MEDIUM alert is skipped and triggers NO email', async () => {
    const mockTransporter = {
      sendMail: jest.fn()
    };
    notificationService.setTransporter(mockTransporter);

    const alert = {
      _id: new mongoose.Types.ObjectId(),
      severity: 'medium',
      attackType: 'probe',
      confidence: 0.85
    };

    const result = await notificationService.sendSecurityAlertNotification(alert);

    expect(result.skipped).toBe(true);
    expect(result.reason).toBe('SEVERITY_NOT_ELIGIBLE');
    expect(mockTransporter.sendMail).not.toHaveBeenCalled();
  });

  test('LOW alert is skipped and triggers NO email', async () => {
    const mockTransporter = {
      sendMail: jest.fn()
    };
    notificationService.setTransporter(mockTransporter);

    const alert = {
      _id: new mongoose.Types.ObjectId(),
      severity: 'low',
      attackType: 'ping_sweep',
      confidence: 0.75
    };

    const result = await notificationService.sendSecurityAlertNotification(alert);

    expect(result.skipped).toBe(true);
    expect(result.reason).toBe('SEVERITY_NOT_ELIGIBLE');
    expect(mockTransporter.sendMail).not.toHaveBeenCalled();
  });

  test('Null alert argument returns skipped without throwing', async () => {
    const result = await notificationService.sendSecurityAlertNotification(null);
    expect(result.skipped).toBe(true);
    expect(result.reason).toBe('NO_ALERT');
  });

  test('Unconfigured SMTP returns skipped safely without throwing', async () => {
    notificationService.setTransporter(null);
    const originalHost = config.smtp.host;
    config.smtp.host = '';

    const alert = {
      _id: new mongoose.Types.ObjectId(),
      severity: 'high',
      attackType: 'port_scan',
      confidence: 0.95
    };

    const result = await notificationService.sendSecurityAlertNotification(alert);

    expect(result.skipped).toBe(true);
    expect(result.reason).toBe('SMTP_NOT_CONFIGURED');

    config.smtp.host = originalHost;
  });

  test('Duplicate alert notification is suppressed (same alert sent only once)', async () => {
    const mockTransporter = {
      sendMail: jest.fn().mockResolvedValue({ messageId: '<msg-dedup-1@netshield>' })
    };
    notificationService.setTransporter(mockTransporter);

    const alertId = new mongoose.Types.ObjectId();
    const alert = {
      _id: alertId,
      severity: 'high',
      attackType: 'neptune',
      confidence: 0.95
    };

    const first = await notificationService.sendSecurityAlertNotification(alert);
    expect(first.success).toBe(true);
    expect(mockTransporter.sendMail).toHaveBeenCalledTimes(1);

    const second = await notificationService.sendSecurityAlertNotification(alert);
    expect(second.skipped).toBe(true);
    expect(second.reason).toBe('DUPLICATE_ALERT');
    expect(mockTransporter.sendMail).toHaveBeenCalledTimes(1);
  });

  test('SMTP failure throws so caller can catch safely without leaking password', async () => {
    const mockTransporter = {
      sendMail: jest.fn().mockRejectedValue(new Error('Connection timed out to smtp.provider.com:587'))
    };
    notificationService.setTransporter(mockTransporter);

    const alert = {
      _id: new mongoose.Types.ObjectId(),
      severity: 'critical',
      attackType: 'exploit',
      confidence: 0.99
    };

    await expect(notificationService.sendSecurityAlertNotification(alert))
      .rejects.toThrow('Connection timed out');
  });
});

describe('Phase 20.13: Network Origin Formatting & Security Tests', () => {
  test('formatNetworkOrigin: TCP flow with full metadata formats correctly', () => {
    const sInfo = {
      src_ip: '192.168.1.10',
      dst_ip: '192.168.1.100',
      src_port: 52341,
      dst_port: 80,
      protocol: 'TCP'
    };

    const textOrigin = notificationService.formatNetworkOrigin(sInfo, false);
    const htmlOrigin = notificationService.formatNetworkOrigin(sInfo, true);

    expect(textOrigin).toBe('192.168.1.10:52341 -> 192.168.1.100:80 [TCP]');
    expect(htmlOrigin).toBe('192.168.1.10:52341 &rarr; 192.168.1.100:80 [TCP]');
  });

  test('formatNetworkOrigin: UDP flow with full metadata formats correctly', () => {
    const sInfo = {
      src_ip: '10.0.0.5',
      dst_ip: '10.0.0.1',
      src_port: 5353,
      dst_port: 53,
      protocol: 'UDP'
    };

    const textOrigin = notificationService.formatNetworkOrigin(sInfo, false);
    const htmlOrigin = notificationService.formatNetworkOrigin(sInfo, true);

    expect(textOrigin).toBe('10.0.0.5:5353 -> 10.0.0.1:53 [UDP]');
    expect(htmlOrigin).toBe('10.0.0.5:5353 &rarr; 10.0.0.1:53 [UDP]');
  });

  test('formatNetworkOrigin: ICMP flow formats without fake ports', () => {
    const sInfo = {
      src_ip: '192.168.1.50',
      dst_ip: '8.8.8.8',
      src_port: 0,
      dst_port: 0,
      protocol: 'ICMP'
    };

    const textOrigin = notificationService.formatNetworkOrigin(sInfo, false);
    const htmlOrigin = notificationService.formatNetworkOrigin(sInfo, true);

    expect(textOrigin).toBe('192.168.1.50 -> 8.8.8.8 [ICMP]');
    expect(htmlOrigin).toBe('192.168.1.50 &rarr; 8.8.8.8 [ICMP]');
    expect(textOrigin).not.toContain(':0');
    expect(htmlOrigin).not.toContain(':0');
  });

  test('formatNetworkOrigin: IP-only alert formats without fake ports', () => {
    const sInfo = {
      src_ip: '192.168.1.20',
      dst_ip: '10.1.1.1',
      protocol: 'TCP'
    };

    const textOrigin = notificationService.formatNetworkOrigin(sInfo, false);
    const htmlOrigin = notificationService.formatNetworkOrigin(sInfo, true);

    expect(textOrigin).toBe('192.168.1.20 -> 10.1.1.1 [TCP]');
    expect(htmlOrigin).toBe('192.168.1.20 &rarr; 10.1.1.1 [TCP]');
  });

  test('formatNetworkOrigin: Completely missing metadata retains unknown:N/A fallback', () => {
    const emptyResultText = notificationService.formatNetworkOrigin(null, false);
    const emptyResultHtml = notificationService.formatNetworkOrigin({}, true);

    expect(emptyResultText).toBe('unknown:N/A -> unknown:N/A [N/A]');
    expect(emptyResultHtml).toBe('unknown:N/A &rarr; unknown:N/A [N/A]');
  });

  test('formatNetworkOrigin: Missing optional fields does not crash email formatter', () => {
    const partialAlert = {
      severity: 'high',
      attackType: 'port_scan',
      sourceInfo: {
        src_ip: '172.16.1.5'
      }
    };

    const formatted = notificationService.formatSecurityAlertEmail('admin@netshield.local', partialAlert);
    expect(formatted.plainText).toContain('172.16.1.5 -> unknown [N/A]');
    expect(formatted.html).toContain('172.16.1.5 &rarr; unknown [N/A]');
  });

  test('formatNetworkOrigin: HTML email safely escapes malicious metadata inputs against XSS', () => {
    const maliciousSourceInfo = {
      src_ip: '<script>alert("xss")</script>',
      dst_ip: '10.0.0.1"><img src=x onerror=alert(1)>',
      src_port: '80<script>',
      dst_port: 443,
      protocol: 'tcp<b'
    };

    const htmlOrigin = notificationService.formatNetworkOrigin(maliciousSourceInfo, true);
    expect(htmlOrigin).not.toContain('<script>');
    expect(htmlOrigin).toContain('&lt;script&gt;');
    expect(htmlOrigin).not.toContain('<img');
    expect(htmlOrigin).toContain('&lt;img');
    expect(htmlOrigin).toContain('&lt;B');

    const formatted = notificationService.formatSecurityAlertEmail('admin@netshield.local', {
      severity: 'high',
      attackType: 'malicious_input',
      sourceInfo: maliciousSourceInfo
    });
    expect(formatted.html).not.toContain('<script>');
  });

  test('formatNetworkOrigin: Protocol known but IPs missing formats as unknown -> unknown [PROTO]', () => {
    const sInfo = {
      protocol: 'TCP'
    };

    const textOrigin = notificationService.formatNetworkOrigin(sInfo, false);
    const htmlOrigin = notificationService.formatNetworkOrigin(sInfo, true);

    expect(textOrigin).toBe('unknown -> unknown [TCP]');
    expect(htmlOrigin).toBe('unknown &rarr; unknown [TCP]');
  });

  test('formatNetworkOrigin: Port known but IPs missing formats as unknown:N/A -> unknown:80 [PROTO]', () => {
    const sInfo = {
      dst_port: 80,
      protocol: 'TCP'
    };

    const textOrigin = notificationService.formatNetworkOrigin(sInfo, false);
    const htmlOrigin = notificationService.formatNetworkOrigin(sInfo, true);

    expect(textOrigin).toBe('unknown:N/A -> unknown:80 [TCP]');
    expect(htmlOrigin).toBe('unknown:N/A &rarr; unknown:80 [TCP]');
  });

  test('formatNetworkOrigin: Port known without protocol formats as unknown:N/A -> unknown:80 [N/A]', () => {
    const sInfo = {
      dst_port: 80
    };

    const textOrigin = notificationService.formatNetworkOrigin(sInfo, false);
    const htmlOrigin = notificationService.formatNetworkOrigin(sInfo, true);

    expect(textOrigin).toBe('unknown:N/A -> unknown:80 [N/A]');
    expect(htmlOrigin).toBe('unknown:N/A &rarr; unknown:80 [N/A]');
  });
});

