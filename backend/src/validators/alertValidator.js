/**
 * Alert Request Validator
 */

const { z } = require('zod');

const updateAlertStatusSchema = z.object({
  status: z.enum(['open', 'acknowledged', 'resolved'], {
    errorMap: () => ({ message: "Invalid alert 'status'. Allowed values: 'open', 'acknowledged', 'resolved'." })
  })
});

const validateUpdateAlertStatus = (data) => {
  const result = updateAlertStatusSchema.safeParse(data);
  if (!result.success) {
    const error = new Error(result.error.issues[0].message);
    error.statusCode = 400;
    throw error;
  }
  return result.data;
};

module.exports = {
  updateAlertStatusSchema,
  validateUpdateAlertStatus
};
