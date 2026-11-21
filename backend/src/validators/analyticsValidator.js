const { z } = require('zod');

const dateStringSchema = z.string().optional().refine((val) => {
  if (!val) return true;
  const d = new Date(val);
  return !isNaN(d.getTime());
}, { message: "Invalid date format. Must be a valid ISO date string." });

const analyticsQuerySchema = z.object({
  datasetType: z.enum(['nsl_kdd', 'cicids2017']).optional(),
  startDate: dateStringSchema,
  endDate: dateStringSchema
}).refine((data) => {
  if (data.startDate && data.endDate) {
    const start = new Date(data.startDate);
    const end = new Date(data.endDate);
    if (start > end) return false;
  }
  return true;
}, { message: "'startDate' must be before or equal to 'endDate'." })
.refine((data) => {
  if (data.startDate && data.endDate) {
    const start = new Date(data.startDate);
    const end = new Date(data.endDate);
    const diffDays = (end - start) / (1000 * 60 * 60 * 24);
    if (diffDays > 90) return false;
  }
  return true;
}, { message: "Date range cannot exceed 90 days." });

const trendsQuerySchema = analyticsQuerySchema.and(
  z.object({
    interval: z.enum(['hour', 'day', 'week']).optional().default('day')
  })
);

const exportQuerySchema = analyticsQuerySchema.and(
  z.object({
    type: z.enum(['predictions', 'alerts', 'analytics'], {
      errorMap: () => ({ message: "Export type must be 'predictions', 'alerts', or 'analytics'." })
    }),
    severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
    prediction: z.string().optional(),
    limit: z.coerce.number().int().min(1).max(5000).optional().default(1000)
  })
);

const activityQuerySchema = z.object({
  timeWindowMinutes: z.coerce.number().int().min(1).max(60).optional().default(15)
});

const validateAnalyticsQuery = (query) => {
  const result = analyticsQuerySchema.safeParse(query);
  if (!result.success) {
    const issue = result.error.issues[0];
    const error = new Error(issue.message);
    error.statusCode = 400;
    throw error;
  }
  return result.data;
};

const validateTrendsQuery = (query) => {
  const result = trendsQuerySchema.safeParse(query);
  if (!result.success) {
    const issue = result.error.issues[0];
    const error = new Error(issue.message);
    error.statusCode = 400;
    throw error;
  }
  return result.data;
};

const validateExportQuery = (query) => {
  const result = exportQuerySchema.safeParse(query);
  if (!result.success) {
    const issue = result.error.issues[0];
    const error = new Error(issue.message);
    error.statusCode = 400;
    throw error;
  }
  return result.data;
};

const validateActivityQuery = (query) => {
  const result = activityQuerySchema.safeParse(query);
  if (!result.success) {
    const issue = result.error.issues[0];
    const error = new Error(issue.message);
    error.statusCode = 400;
    throw error;
  }
  return result.data;
};

module.exports = {
  validateAnalyticsQuery,
  validateTrendsQuery,
  validateExportQuery,
  validateActivityQuery
};
