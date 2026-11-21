/**
 * NetShield Centralized Dynamic Settings Service
 * Provides cached, dynamic configuration lookup with instant invalidation on mutation.
 */

const Setting = require('../models/Setting');
const logger = require('../utils/logger') || console;

const DEFAULT_SETTINGS = [
  { key: 'alertThresholdConfidence', value: 80, description: 'Minimum model confidence required to trigger high severity alert.' },
  { key: 'enableAutoResolution', value: false, description: 'Automatically resolve alerts when benign traffic resumes.' },
  { key: 'maxLogRetentionDays', value: 30, description: 'Number of days to retain threat prediction logs in MongoDB.' },
  { key: 'systemNotificationEmail', value: 'admin@netshield.local', description: 'Contact email for security threat digests.' }
];

// In-memory cache for ultra-fast request-time lookups without querying MongoDB on every packet
const cache = new Map();

/**
 * Retrieves setting value by key, checking cache first, then MongoDB.
 * @param {string} key - Setting key identifier
 * @param {any} defaultValue - Fallback value if setting document does not exist
 * @returns {Promise<any>}
 */
const getSetting = async (key, defaultValue) => {
  if (cache.has(key)) {
    return cache.get(key);
  }

  try {
    const doc = await Setting.findOne({ key }).lean();
    if (doc && doc.value !== undefined && doc.value !== null) {
      cache.set(key, doc.value);
      return doc.value;
    }
  } catch (err) {
    logger.error?.(`[SettingsService] Failed to load setting '${key}' from DB:`, err.message);
  }

  // Fallback to default
  const defaultEntry = DEFAULT_SETTINGS.find(s => s.key === key);
  const fallback = defaultEntry ? defaultEntry.value : defaultValue;
  cache.set(key, fallback);
  return fallback;
};

/**
 * Invalidates cached setting value, ensuring immediate propagation across runtime consumers.
 * @param {string} [key] - Optional specific key to invalidate. If omitted, clears all cache.
 */
const invalidateCache = (key) => {
  if (key) {
    cache.delete(key);
  } else {
    cache.clear();
  }
};

/**
 * Returns all settings from DB, seeding defaults if the collection is empty.
 * @returns {Promise<Array>}
 */
const getAllSettings = async () => {
  let settings = await Setting.find({}).sort({ key: 1 }).lean();
  if (settings.length === 0) {
    await Setting.insertMany(DEFAULT_SETTINGS);
    settings = await Setting.find({}).sort({ key: 1 }).lean();
  }
  return settings;
};

module.exports = {
  getSetting,
  invalidateCache,
  getAllSettings,
  DEFAULT_SETTINGS
};
