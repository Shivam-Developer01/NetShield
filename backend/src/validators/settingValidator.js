/**
 * Setting Request Validator
 * Validates updates to system dynamic configuration parameters.
 */

const { z } = require('zod');

const validateSettingValue = (key, value) => {
  if (value === undefined || value === null) {
    const error = new Error(`Setting '${key}': 'value' cannot be null or undefined.`);
    error.statusCode = 400;
    throw error;
  }

  switch (key) {
    case 'alertThresholdConfidence': {
      if (typeof value !== 'number' || isNaN(value)) {
        const error = new Error("alertThresholdConfidence must be a valid number between 0 and 100.");
        error.statusCode = 400;
        throw error;
      }
      if (value < 0 || value > 100) {
        const error = new Error("alertThresholdConfidence must be between 0 and 100.");
        error.statusCode = 400;
        throw error;
      }
      return value;
    }

    case 'enableAutoResolution': {
      if (typeof value !== 'boolean') {
        const error = new Error("enableAutoResolution must be a boolean (true or false).");
        error.statusCode = 400;
        throw error;
      }
      return value;
    }

    case 'maxLogRetentionDays': {
      if (typeof value !== 'number' || isNaN(value) || !Number.isInteger(value)) {
        const error = new Error("maxLogRetentionDays must be an integer number of days.");
        error.statusCode = 400;
        throw error;
      }
      if (value < 1 || value > 3650) {
        const error = new Error("maxLogRetentionDays must be between 1 and 3650 days.");
        error.statusCode = 400;
        throw error;
      }
      return value;
    }

    case 'systemNotificationEmail': {
      if (typeof value !== 'string') {
        const error = new Error("systemNotificationEmail must be a string.");
        error.statusCode = 400;
        throw error;
      }
      const trimmed = value.trim();
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!trimmed || !emailRegex.test(trimmed)) {
        const error = new Error("systemNotificationEmail must be a valid email address.");
        error.statusCode = 400;
        throw error;
      }
      return trimmed;
    }

    default:
      return value;
  }
};

const updateSettingSchema = z.object({
  value: z.any().refine(val => val !== undefined, {
    message: "'value' field is required to update setting."
  }),
  description: z.string().optional()
});

const validateUpdateSetting = (key, data) => {
  const result = updateSettingSchema.safeParse(data);
  if (!result.success) {
    const error = new Error(result.error.issues[0].message);
    error.statusCode = 400;
    throw error;
  }

  const validatedValue = validateSettingValue(key, result.data.value);
  return {
    value: validatedValue,
    description: result.data.description
  };
};

module.exports = {
  updateSettingSchema,
  validateUpdateSetting,
  validateSettingValue
};
