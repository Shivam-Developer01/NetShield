const { z } = require('zod');

const incidentQuerySchema = z.object({
  status: z.enum(['OPEN', 'ACKNOWLEDGED', 'RESOLVED']).optional(),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
  source: z.string().optional(),
  page: z.string().transform(v => parseInt(v, 10)).pipe(z.number().min(1)).optional().default('1'),
  limit: z.string().transform(v => parseInt(v, 10)).pipe(z.number().min(1).max(100)).optional().default('20')
});

const incidentUpdateSchema = z.object({
  status: z.enum(['ACKNOWLEDGED', 'RESOLVED']),
  notes: z.string().max(500).optional()
});

module.exports = {
  incidentQuerySchema,
  incidentUpdateSchema
};
