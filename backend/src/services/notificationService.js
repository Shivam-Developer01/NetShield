/**
 * NetShield Security Notification & Threat Digest Service
 * Dispatches automated digests and critical alert notifications to configured recipient.
 * Dynamically resolves recipient email from settingsService.
 * Supports production SMTP delivery (Gmail/RFC SMTP) and offline/test stub mode.
 */

const nodemailer = require('nodemailer');
const Alert = require('../models/Alert');
const settingsService = require('./settingsService');
const config = require('../config/env');
const logger = require('../utils/logger') || console;

let customTransporter = null;

/**
 * Injects a mock transporter for testing.
 * @param {Object|null} transporter 
 */
const setTransporter = (transporter) => {
  customTransporter = transporter;
};

/**
 * Returns active Nodemailer transporter, creating one if configured.
 * @returns {Object|null}
 */
const getTransporter = () => {
  if (customTransporter) {
    return customTransporter;
  }
  if (!config.smtp.isConfigured) {
    return null;
  }
  return nodemailer.createTransport({
    host: config.smtp.host,
    port: config.smtp.port,
    secure: config.smtp.secure,
    auth: {
      user: config.smtp.user,
      pass: config.smtp.pass
    },
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000
  });
};

/**
 * Safely verifies SMTP transport connection and authentication.
 * Does not send any email and never leaks credentials.
 * @returns {Promise<{ success: boolean, host?: string, port?: number, secure?: boolean, error?: string, code?: string }>}
 */
const verifySmtpConnection = async () => {
  if (!config.smtp.isConfigured && !customTransporter) {
    return {
      success: false,
      error: 'SMTP is not configured. Please set SMTP_HOST, SMTP_USER, and SMTP_PASS in environment.',
      code: 'SMTP_NOT_CONFIGURED'
    };
  }

  try {
    const transporter = getTransporter();
    if (!transporter) {
      return {
        success: false,
        error: 'Failed to initialize SMTP transport.',
        code: 'TRANSPORT_INIT_FAILED'
      };
    }
    await transporter.verify();
    logger.info?.(`[Notification Service] SMTP connection verified successfully with ${config.smtp.host}:${config.smtp.port}`);
    return {
      success: true,
      host: config.smtp.host,
      port: config.smtp.port,
      secure: config.smtp.secure
    };
  } catch (err) {
    logger.error?.('[Notification Service] SMTP connection verification failed:', err.message);
    return {
      success: false,
      error: err.message,
      code: err.code || 'VERIFICATION_FAILED'
    };
  }
};

/**
 * Returns currently configured notification contact email.
 * @returns {Promise<string>}
 */
const getNotificationEmail = async () => {
  return await settingsService.getSetting('systemNotificationEmail', 'admin@netshield.local');
};

const escapeHtml = (str) => String(str || '').replace(/[&<>"']/g, (m) => ({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;'
}[m]));

const { formatNetworkOrigin } = require('../utils/originResolver');

/**
 * Builds HTML and Plaintext content for security threat digest.
 */
const formatThreatDigest = (recipient, alerts) => {
  const count = alerts.length;
  const timestamp = new Date().toUTCString();

  const textAlerts = count > 0 
    ? alerts.map((a, idx) => `[${idx + 1}] Severity: ${a.severity.toUpperCase()} | Attack: ${a.attackType} | Dataset: ${a.datasetType} | Confidence: ${(a.confidence * 100).toFixed(1)}% | Time: ${new Date(a.timestamp).toISOString()}`).join('\n')
    : 'No High or Critical severity alerts detected in the last 24 hours.';

  const plainText = `NetShield SOC Threat Digest
Generated: ${timestamp}
Recipient: ${recipient}
High/Critical Threat Alerts: ${count}

Summary of Recent Threats (Last 24 Hours):
${textAlerts}

--
NetShield Automated Security Notification System
This is a secure automated transmission. Do not reply directly to this email.`;

  const alertRows = count > 0
    ? alerts.map((a) => {
        const sevColor = a.severity.toLowerCase() === 'critical' ? '#dc2626' : '#ea580c';
        const confPercent = (a.confidence * 100).toFixed(1);
        return `
          <tr style="border-bottom: 1px solid #334155;">
            <td style="padding: 10px 12px; font-family: monospace; font-size: 13px; color: #f8fafc;">${escapeHtml(new Date(a.timestamp).toLocaleTimeString())}</td>
            <td style="padding: 10px 12px;">
              <span style="background-color: ${sevColor}20; color: ${sevColor}; border: 1px solid ${sevColor}40; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 12px; text-transform: uppercase;">
                ${escapeHtml(a.severity)}
              </span>
            </td>
            <td style="padding: 10px 12px; font-weight: 600; color: #f1f5f9; font-size: 13px;">${escapeHtml(a.attackType)}</td>
            <td style="padding: 10px 12px; font-family: monospace; font-size: 12px; color: #94a3b8;">${escapeHtml(a.datasetType)}</td>
            <td style="padding: 10px 12px; font-family: monospace; font-size: 13px; color: #38bdf8; font-weight: 600;">${confPercent}%</td>
          </tr>
        `;
      }).join('')
    : `<tr><td colspan="5" style="padding: 24px; text-align: center; color: #94a3b8; font-size: 14px;">No high or critical alerts recorded in the past 24 hours. Traffic is normal.</td></tr>`;

  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NetShield Security Threat Digest</title>
</head>
<body style="margin: 0; padding: 0; background-color: #090d16; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #e2e8f0;">
  <div style="max-width: 680px; margin: 24px auto; background-color: #0f172a; border-radius: 8px; border: 1px solid #1e293b; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
    
    <!-- Header -->
    <div style="background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); padding: 24px 32px; border-bottom: 2px solid #0284c7;">
      <table style="width: 100%; border-collapse: collapse;">
        <tr>
          <td>
            <div style="display: inline-block; font-size: 20px; font-weight: 800; letter-spacing: -0.5px; color: #38bdf8;">
              🛡️ NETSHIELD <span style="font-weight: 400; color: #94a3b8; font-size: 14px;">| SOC Threat Digest</span>
            </div>
          </td>
          <td style="text-align: right;">
            <span style="background-color: #0369a120; color: #38bdf8; border: 1px solid #0284c740; padding: 4px 10px; border-radius: 12px; font-size: 11px; font-weight: 600;">
              CONFIDENTIAL
            </span>
          </td>
        </tr>
      </table>
    </div>

    <!-- Overview Banner -->
    <div style="padding: 24px 32px; background-color: #1e293b40; border-bottom: 1px solid #1e293b;">
      <p style="margin: 0 0 8px 0; font-size: 14px; color: #94a3b8;">Automated 24-Hour Security Threat Digest for <strong style="color: #f1f5f9;">${escapeHtml(recipient)}</strong></p>
      <div style="display: flex; gap: 16px; margin-top: 12px;">
        <div style="background-color: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 12px 16px; min-width: 120px;">
          <div style="font-size: 11px; text-transform: uppercase; color: #64748b; font-weight: 700;">Threat Count</div>
          <div style="font-size: 24px; font-weight: 800; color: ${count > 0 ? '#ef4444' : '#22c55e'}; margin-top: 4px;">${count}</div>
        </div>
        <div style="background-color: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 12px 16px; min-width: 160px;">
          <div style="font-size: 11px; text-transform: uppercase; color: #64748b; font-weight: 700;">Generated At</div>
          <div style="font-size: 13px; font-weight: 600; color: #cbd5e1; margin-top: 8px;">${escapeHtml(timestamp)}</div>
        </div>
      </div>
    </div>

    <!-- Alert Breakdown Table -->
    <div style="padding: 24px 32px;">
      <h3 style="margin: 0 0 16px 0; font-size: 15px; font-weight: 700; color: #f8fafc; text-transform: uppercase; letter-spacing: 0.5px;">
        Priority Threat Incidents
      </h3>
      <div style="overflow-x: auto;">
        <table style="width: 100%; border-collapse: collapse; text-align: left;">
          <thead>
            <tr style="background-color: #1e293b; color: #94a3b8; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px;">
              <th style="padding: 10px 12px; border-top-left-radius: 4px;">Time</th>
              <th style="padding: 10px 12px;">Severity</th>
              <th style="padding: 10px 12px;">Threat Classification</th>
              <th style="padding: 10px 12px;">Sensor/Model</th>
              <th style="padding: 10px 12px; border-top-right-radius: 4px;">Confidence</th>
            </tr>
          </thead>
          <tbody>
            ${alertRows}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Footer -->
    <div style="padding: 20px 32px; background-color: #090d16; border-top: 1px solid #1e293b; font-size: 12px; color: #64748b; line-height: 1.5;">
      <p style="margin: 0 0 6px 0;">This email was automatically generated by the NetShield Intrusion Detection Microservice for administrative recipient: <span style="color: #94a3b8;">${escapeHtml(recipient)}</span>.</p>
      <p style="margin: 0;">To modify alert dispatch policies or notification recipients, sign in to the NetShield SOC Dashboard under <strong>Settings &gt; System Notification Email</strong>.</p>
    </div>
  </div>
</body>
</html>
  `;

  return { plainText, html };
};

/**
 * Dispatches exactly one test email to verify real SMTP delivery.
 * @param {Object} [params]
 * @param {string} [params.recipient] - Optional recipient override, defaults to systemNotificationEmail
 * @returns {Promise<{ success: boolean, recipient: string, messageId: string, transport: string }>}
 */
const sendTestEmail = async (params = {}) => {
  const recipient = params.recipient || (await getNotificationEmail());

  if (!recipient || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recipient)) {
    const err = new Error('Invalid or unconfigured recipient email address.');
    err.code = 'INVALID_RECIPIENT';
    throw err;
  }

  const transporter = getTransporter();
  if (!transporter) {
    const err = new Error('SMTP is not configured. Configure SMTP_HOST, SMTP_USER, and SMTP_PASS before attempting real delivery.');
    err.code = 'SMTP_NOT_CONFIGURED';
    throw err;
  }

  const subject = 'NetShield SMTP Test';
  const text = 'This is a test email from NetShield. SMTP delivery is configured successfully.';
  const timestamp = new Date().toUTCString();

  const html = `
<!DOCTYPE html>
<html>
<body style="margin: 0; padding: 0; background-color: #090d16; font-family: sans-serif; color: #e2e8f0;">
  <div style="max-width: 540px; margin: 32px auto; background-color: #0f172a; border-radius: 8px; border: 1px solid #1e293b; padding: 28px; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
    <div style="font-size: 18px; font-weight: 800; color: #38bdf8; margin-bottom: 16px;">
      🛡️ NETSHIELD | SMTP Connectivity Test
    </div>
    <div style="background-color: #10b98120; border: 1px solid #10b98140; color: #34d399; padding: 12px 16px; border-radius: 6px; font-weight: 600; font-size: 14px; margin-bottom: 18px;">
      ✅ SMTP Delivery Successful
    </div>
    <p style="font-size: 14px; color: #cbd5e1; line-height: 1.6; margin: 0 0 16px 0;">
      This is a test email dispatched from your NetShield Intrusion Detection System. Your SMTP email transport configuration is verified and active.
    </p>
    <table style="width: 100%; border-collapse: collapse; font-size: 12px; color: #94a3b8; background-color: #1e293b50; border-radius: 4px;">
      <tr>
        <td style="padding: 8px 12px; font-weight: 600;">Recipient:</td>
        <td style="padding: 8px 12px; color: #f1f5f9; font-family: monospace;">${escapeHtml(recipient)}</td>
      </tr>
      <tr>
        <td style="padding: 8px 12px; font-weight: 600;">Sender:</td>
        <td style="padding: 8px 12px; color: #f1f5f9; font-family: monospace;">${escapeHtml(config.smtp.from)}</td>
      </tr>
      <tr>
        <td style="padding: 8px 12px; font-weight: 600;">Timestamp:</td>
        <td style="padding: 8px 12px; color: #f1f5f9; font-family: monospace;">${escapeHtml(timestamp)}</td>
      </tr>
    </table>
    <p style="font-size: 11px; color: #64748b; margin-top: 24px; margin-bottom: 0; text-align: center;">
      NetShield Cyber Threat Intelligence System • Automated Notification Test
    </p>
  </div>
</body>
</html>
  `;

  try {
    const info = await transporter.sendMail({
      from: config.smtp.from,
      to: recipient,
      subject,
      text,
      html
    });

    logger.info?.(`[Notification Service] SMTP test email successfully sent to ${recipient} (messageId: ${info.messageId})`);

    return {
      success: true,
      recipient,
      messageId: info.messageId,
      transport: 'SMTP'
    };
  } catch (err) {
    logger.error?.('[Notification Service] SMTP test email delivery failed:', err.message);
    throw err;
  }
};

/**
 * Dispatches a security threat digest notification to the configured recipient.
 * In TEST mode or when SMTP is unconfigured, operates in safe stub mode without sending external emails.
 * In REAL mode (when testMode is explicitly false and SMTP is configured), dispatches an authentic email.
 * @param {Object} [options]
 * @param {boolean} [options.testMode=false] - Force safe test mode
 * @returns {Promise<{ success: boolean, recipient: string, alertCount: number, dispatchedAt: Date, transport: string, messageId?: string }>}
 */
const dispatchThreatDigest = async (options = {}) => {
  try {
    const recipient = await getNotificationEmail();

    // Fetch recent high/critical alerts (last 24 hours or latest 20)
    const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const recentAlerts = await Alert.find({
      severity: { $in: ['high', 'critical'] },
      timestamp: { $gte: cutoff }
    })
    .sort({ timestamp: -1 })
    .limit(20)
    .lean();

    const isRealDispatch = !options.testMode && (config.smtp.isConfigured || Boolean(customTransporter));
    const transportType = isRealDispatch ? 'SMTP' : 'TEST_STUB_NO_SMTP';

    const alertsSummary = recentAlerts.map(a => ({
      id: a._id,
      severity: a.severity,
      attackType: a.attackType,
      datasetType: a.datasetType,
      confidence: a.confidence,
      timestamp: a.timestamp
    }));

    let messageId = null;

    if (isRealDispatch) {
      const transporter = getTransporter();
      if (!transporter) {
        throw new Error('Transporter unavailable for real dispatch.');
      }

      const { plainText, html } = formatThreatDigest(recipient, alertsSummary);

      const info = await transporter.sendMail({
        from: config.smtp.from,
        to: recipient,
        subject: `NetShield Security Threat Digest - ${alertsSummary.length} Priority Alert(s)`,
        text: plainText,
        html
      });

      messageId = info.messageId;
      logger.info?.(`[Notification Service] Real threat digest email dispatched to ${recipient} (${alertsSummary.length} alerts, messageId: ${messageId})`);
    } else {
      logger.info?.(`[Notification Service] Threat digest prepared in safe test stub mode for ${recipient} (${alertsSummary.length} alerts, transport: ${transportType})`);
    }

    const result = {
      success: true,
      recipient,
      alertCount: recentAlerts.length,
      alerts: alertsSummary,
      dispatchedAt: new Date(),
      transport: transportType
    };

    if (messageId) {
      result.messageId = messageId;
    }

    return result;
  } catch (err) {
    logger.error?.('[Notification Service Error]', err.message);
    throw err;
  }
};

/**
 * Builds HTML and plain-text fallback content for an individual HIGH or CRITICAL security alert.
 * @param {string} recipient
 * @param {Object} alert
 * @returns {{ subject: string, plainText: string, html: string }}
 */
const formatSecurityAlertEmail = (recipient, alert) => {
  const severity = String(alert.severity || '').toLowerCase();
  const sevUpper = severity.toUpperCase();
  const sevColor = severity === 'critical' ? '#ef4444' : '#f97316';
  const attackType = alert.attackType || alert.prediction || 'Unknown Threat';
  const confidencePct = typeof alert.confidence === 'number' ? `${(alert.confidence * 100).toFixed(1)}%` : 'N/A';
  const timestamp = alert.timestamp ? new Date(alert.timestamp).toUTCString() : new Date().toUTCString();
  const alertId = alert._id ? String(alert._id) : 'N/A';
  const dataset = alert.datasetType || 'N/A';
  const modelVersion = alert.modelVersion || 'N/A';
  const description = alert.description || 'Malicious intrusion behavior detected by ML inference pipeline.';

  const sInfo = alert.sourceInfo || {};
  const srcIp = sInfo.src_ip || sInfo['Source IP'] || 'unknown';
  const dstIp = sInfo.dst_ip || sInfo['Destination IP'] || 'unknown';
  const srcPort = sInfo.src_port !== undefined ? sInfo.src_port : (sInfo['Source Port'] !== undefined ? sInfo['Source Port'] : 'N/A');
  const dstPort = sInfo.dst_port !== undefined ? sInfo.dst_port : (sInfo['Destination Port'] !== undefined ? sInfo['Destination Port'] : 'N/A');
  const protocol = sInfo.protocol || sInfo['Protocol'] || sInfo.protocol_type || 'N/A';
  const flowId = sInfo.flow_id || sInfo.flowId || null;

  const subject = `[NetShield] ${sevUpper} Security Alert — ${attackType}`;
  const plainOrigin = formatNetworkOrigin(alert.sourceInfo, false);
  const htmlOrigin = formatNetworkOrigin(alert.sourceInfo, true);

  const plainText = `[NetShield Security Alert]
Severity: ${sevUpper}
Threat Type: ${attackType}
Prediction Label: ${alert.prediction || attackType}
Confidence: ${confidencePct}
Dataset: ${dataset} (Model: ${modelVersion})
Timestamp: ${timestamp}
Alert ID: ${alertId}
${flowId ? `Flow ID: ${flowId}\n` : ''}Network Origin:
${plainOrigin}
Network 5-Tuple:
- Source IP: ${srcIp}
- Source Port: ${srcPort}
- Destination IP: ${dstIp}
- Destination Port: ${dstPort}
- Protocol: ${protocol}

Description:
${description}

Recommended Action:
Inspect the NetShield SOC Dashboard immediately to review correlated flows and take containment action if necessary.

--
NetShield Automated Security Notification System
This is a secure automated alert transmission. Do not reply directly to this email.`;

  const html = `
<!DOCTYPE html>
<html>
<body style="margin: 0; padding: 0; background-color: #090d16; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #e2e8f0;">
  <div style="max-width: 580px; margin: 28px auto; background-color: #0f172a; border-radius: 8px; border: 1px solid #1e293b; padding: 28px; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
    <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 14px; margin-bottom: 20px;">
      <div style="font-size: 18px; font-weight: 800; color: #38bdf8;">
        🛡️ NETSHIELD SOC | Real-Time Security Alert
      </div>
    </div>
    <div style="background-color: ${sevColor}15; border-left: 4px solid ${sevColor}; padding: 12px 16px; border-radius: 4px; margin-bottom: 20px;">
      <div style="font-size: 11px; font-weight: 700; color: ${sevColor}; text-transform: uppercase; letter-spacing: 0.5px;">
        ${sevUpper} SEVERITY INTRUSION DETECTED
      </div>
      <div style="font-size: 16px; font-weight: 700; color: #f8fafc; margin-top: 4px;">
        ${escapeHtml(attackType)} (${escapeHtml(confidencePct)} Confidence)
      </div>
    </div>
    <table style="width: 100%; border-collapse: collapse; font-size: 12px; color: #94a3b8; background-color: #1e293b50; border-radius: 6px; margin-bottom: 20px;">
      <tr>
        <td style="padding: 8px 12px; font-weight: 600; width: 32%;">Alert ID:</td>
        <td style="padding: 8px 12px; color: #f1f5f9; font-family: monospace;">${escapeHtml(alertId)}</td>
      </tr>
      <tr style="border-top: 1px solid #1e293b;">
        <td style="padding: 8px 12px; font-weight: 600;">Detection Model:</td>
        <td style="padding: 8px 12px; color: #f1f5f9;">${escapeHtml(dataset)} (${escapeHtml(modelVersion)})</td>
      </tr>
      <tr style="border-top: 1px solid #1e293b;">
        <td style="padding: 8px 12px; font-weight: 600;">Network Origin:</td>
        <td style="padding: 8px 12px; color: #f1f5f9; font-family: monospace;">${htmlOrigin}</td>
      </tr>
      ${flowId ? `
      <tr style="border-top: 1px solid #1e293b;">
        <td style="padding: 8px 12px; font-weight: 600;">Flow ID:</td>
        <td style="padding: 8px 12px; color: #f1f5f9; font-family: monospace;">${escapeHtml(flowId)}</td>
      </tr>` : ''}
      <tr style="border-top: 1px solid #1e293b;">
        <td style="padding: 8px 12px; font-weight: 600;">Timestamp:</td>
        <td style="padding: 8px 12px; color: #f1f5f9; font-family: monospace;">${escapeHtml(timestamp)}</td>
      </tr>
      <tr style="border-top: 1px solid #1e293b;">
        <td style="padding: 8px 12px; font-weight: 600;">Assessment:</td>
        <td style="padding: 8px 12px; color: #cbd5e1;">${escapeHtml(description)}</td>
      </tr>
    </table>
    <div style="background-color: #0c1322; border: 1px solid #1e293b; padding: 12px 16px; border-radius: 6px; font-size: 12px; color: #94a3b8; line-height: 1.5;">
      <span style="font-weight: 700; color: #38bdf8;">SOC Action Required:</span> Please access the NetShield Operations dashboard to acknowledge, investigate, or isolate affected network endpoints.
    </div>
    <p style="font-size: 11px; color: #64748b; margin-top: 24px; margin-bottom: 0; text-align: center;">
      NetShield Cyber Threat Intelligence System • Automated High-Priority Alert Transmission
    </p>
  </div>
</body>
</html>
  `;

  return { subject, plainText, html };
};

const dispatchedAlertIds = new Set();

/**
 * Clears the in-memory dispatched alert cache (useful for testing).
 */
const clearDispatchedAlerts = () => {
  dispatchedAlertIds.clear();
};

/**
 * Dispatches an automated security alert email for newly created HIGH or CRITICAL alerts.
 * Operates non-blockingly and safely degrades if SMTP is unconfigured or fails.
 * @param {Object} alert - The saved Alert document or alert object
 * @returns {Promise<{ success?: boolean, skipped?: boolean, reason?: string, recipient?: string, messageId?: string, alertId?: string }>}
 */
const sendSecurityAlertNotification = async (alert) => {
  if (!alert) {
    return { skipped: true, reason: 'NO_ALERT' };
  }

  const severity = String(alert.severity || '').toLowerCase();
  if (severity !== 'high' && severity !== 'critical') {
    return { skipped: true, reason: 'SEVERITY_NOT_ELIGIBLE', severity };
  }

  const alertId = alert._id ? String(alert._id) : null;
  if (alertId && dispatchedAlertIds.has(alertId)) {
    logger.debug?.(`[Notification Service] Skipping duplicate alert notification for alert ${alertId}`);
    return { skipped: true, reason: 'DUPLICATE_ALERT', alertId };
  }

  const transporter = getTransporter();
  if (!transporter) {
    logger.debug?.('[Notification Service] SMTP not configured; skipping automatic alert email.');
    return { skipped: true, reason: 'SMTP_NOT_CONFIGURED' };
  }

  const recipient = await getNotificationEmail();
  if (!recipient || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recipient)) {
    logger.warn?.(`[Notification Service] Invalid systemNotificationEmail "${recipient}"; skipping alert email.`);
    return { skipped: true, reason: 'INVALID_RECIPIENT' };
  }

  const { subject, plainText, html } = formatSecurityAlertEmail(recipient, alert);

  try {
    const info = await transporter.sendMail({
      from: config.smtp.from,
      to: recipient,
      subject,
      text: plainText,
      html
    });

    if (alertId) {
      dispatchedAlertIds.add(alertId);
      if (dispatchedAlertIds.size > 1000) {
        const firstEntry = dispatchedAlertIds.values().next().value;
        dispatchedAlertIds.delete(firstEntry);
      }
    }

    logger.info?.(`[Notification Service] Automated ${severity.toUpperCase()} security alert email sent to ${recipient} (messageId: ${info.messageId}, alertId: ${alertId || 'N/A'})`);

    return {
      success: true,
      recipient,
      messageId: info.messageId,
      alertId,
      severity
    };
  } catch (err) {
    logger.error?.('[Notification Service] Automated security alert email delivery failed:', err.message);
    throw err;
  }
};

module.exports = {
  getNotificationEmail,
  dispatchThreatDigest,
  sendTestEmail,
  verifySmtpConnection,
  formatThreatDigest,
  formatNetworkOrigin,
  formatSecurityAlertEmail,
  sendSecurityAlertNotification,
  clearDispatchedAlerts,
  setTransporter,
  getTransporter
};

