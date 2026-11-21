/**
 * Prediction Request Validator
 * Protects API boundary by validating datasetType and non-empty feature object
 * while allowing FastAPI to serve as authoritative feature-schema validator.
 */

const { z } = require('zod');

const predictionSchema = z.object({
  datasetType: z.enum(['nsl_kdd', 'cicids2017'], {
    errorMap: () => ({ message: "Invalid 'datasetType'. Must be 'nsl_kdd' or 'cicids2017'." })
  }),
  inputData: z.record(z.any()).refine(
    (obj) => obj && Object.keys(obj).length > 0,
    { message: "'inputData' must be a non-empty object containing feature values." }
  ),
  sourceInfo: z.record(z.any()).optional()
});

const validatePredictionInput = (data) => {
  const result = predictionSchema.safeParse(data);
  if (!result.success) {
    const issue = result.error.issues[0];
    const error = new Error(issue.message);
    error.statusCode = 400;
    throw error;
  }
  return result.data;
};

module.exports = {
  predictionSchema,
  validatePredictionInput
};
