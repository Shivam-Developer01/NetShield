/**
 * NetShield Prediction Log Retention Service
 * Manages automated lifecycle and retention purging for prediction logs.
 * Note: Only purges raw prediction logs from the 'Log' collection.
 * Security alerts, incidents, users, and audit logs are strictly preserved.
 */

const Log = require('../models/Log');
const settingsService = require('./settingsService');
const logger = require('../utils/logger') || console;

/**
 * Executes retention pruning of prediction logs based on configured maxLogRetentionDays.
 * @param {number} [daysOverride] - Optional days parameter for testing or explicit invocation
 * @returns {Promise<{ success: boolean, deletedCount: number, cutoffDate: Date, retentionDays: number }>}
 */
const enforceLogRetention = async (daysOverride) => {
  try {
    let days = daysOverride;
    if (days === undefined || days === null) {
      days = await settingsService.getSetting('maxLogRetentionDays', 30);
    }

    const numDays = Number(days);
    if (isNaN(numDays) || numDays <= 0) {
      throw new Error(`Invalid retention days specified: ${days}`);
    }

    const cutoffDate = new Date(Date.now() - numDays * 24 * 60 * 60 * 1000);
    
    // Purge only documents from Log collection older than cutoffDate
    const result = await Log.deleteMany({ timestamp: { $lt: cutoffDate } });

    logger.info?.(`[Retention Service] Pruned ${result.deletedCount} prediction logs older than ${cutoffDate.toISOString()} (${numDays} days)`);

    return {
      success: true,
      deletedCount: result.deletedCount,
      cutoffDate,
      retentionDays: numDays
    };
  } catch (err) {
    logger.error?.('[Retention Service Error]', err.message);
    throw err;
  }
};

module.exports = {
  enforceLogRetention
};
