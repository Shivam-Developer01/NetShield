/**
 * Setting Controller
 * Serves and updates dynamic system settings with instant cache invalidation
 * and automated triggers for retention and notifications.
 */

const Setting = require('../models/Setting');
const { validateUpdateSetting } = require('../validators/settingValidator');
const settingsService = require('../services/settingsService');
const retentionService = require('../services/retentionService');
const notificationService = require('../services/notificationService');
const logger = require('../utils/logger') || console;

const getSettings = async (req, res, next) => {
  try {
    const settings = await settingsService.getAllSettings();
    res.status(200).json({
      success: true,
      data: settings
    });
  } catch (error) {
    next(error);
  }
};

const updateSettingByKey = async (req, res, next) => {
  try {
    const key = req.params.key;
    const validated = validateUpdateSetting(key, req.body);
    const { value, description } = validated;

    const updateFields = {
      value,
      updatedAt: new Date()
    };
    if (description !== undefined) {
      updateFields.description = description;
    }

    const setting = await Setting.findOneAndUpdate(
      { key },
      { $set: updateFields },
      { new: true, upsert: true, runValidators: true }
    ).lean();

    // Invalidate runtime settings cache immediately
    settingsService.invalidateCache(key);

    // If maxLogRetentionDays was changed, trigger immediate retention cleanup
    if (key === 'maxLogRetentionDays') {
      retentionService.enforceLogRetention(value).catch(err => {
        logger.error?.('[Settings] Automated retention cleanup error:', err.message);
      });
    }

    res.status(200).json({
      success: true,
      data: setting
    });
  } catch (error) {
    next(error);
  }
};

const triggerDigestNotification = async (req, res, next) => {
  try {
    // Only dispatch real email if explicitly requested via real: true or mode: 'real',
    // otherwise default to safe testMode: true so tests and accidental calls are always safe.
    const isRealRequested = req.body?.mode === 'real' || req.body?.real === true || req.query?.real === 'true';
    const testMode = !isRealRequested;

    const result = await notificationService.dispatchThreatDigest({ testMode });
    res.status(200).json({
      success: true,
      data: result
    });
  } catch (error) {
    next(error);
  }
};

/**
 * ADMIN-only endpoint to send a dedicated SMTP test email.
 * Dispatches a single test email to the current systemNotificationEmail recipient.
 */
const sendTestEmail = async (req, res, next) => {
  try {
    const recipient = await settingsService.getSetting('systemNotificationEmail', 'admin@netshield.local');
    const result = await notificationService.sendTestEmail({ recipient });
    res.status(200).json({
      success: true,
      data: result
    });
  } catch (error) {
    if (error.code === 'SMTP_NOT_CONFIGURED' || error.message?.includes('SMTP is not configured')) {
      return res.status(400).json({
        success: false,
        error: 'SMTP_NOT_CONFIGURED',
        message: 'SMTP is not configured. Please define SMTP_HOST, SMTP_USER, and SMTP_PASS in environment variables.'
      });
    }
    if (error.code === 'INVALID_RECIPIENT') {
      return res.status(400).json({
        success: false,
        error: 'INVALID_RECIPIENT',
        message: error.message
      });
    }
    logger.error?.('[SettingsController] Test email failed:', error.message);
    res.status(502).json({
      success: false,
      error: 'SMTP_DELIVERY_FAILED',
      message: error.message || 'Failed to dispatch SMTP test email.'
    });
  }
};

/**
 * ADMIN-only diagnostic endpoint to check SMTP connectivity without sending email.
 */
const checkSmtpStatus = async (req, res, next) => {
  try {
    const result = await notificationService.verifySmtpConnection();
    res.status(200).json({
      success: result.success,
      data: result
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  getSettings,
  updateSettingByKey,
  triggerDigestNotification,
  sendTestEmail,
  checkSmtpStatus
};
