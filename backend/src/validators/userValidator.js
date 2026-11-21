const { z } = require('zod');

const updateUserSchema = z.object({
  username: z.string().min(2).optional(),
  email: z.string().email().optional(),
  role: z.enum(['ADMIN', 'ANALYST', 'VIEWER']).optional(),
  isActive: z.boolean().optional()
});

const validateUpdateUser = (req, res, next) => {
  try {
    req.body = updateUserSchema.parse(req.body);
    next();
  } catch (error) {
    return res.status(400).json({
      success: false,
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Invalid user update parameters',
        details: error.errors
      }
    });
  }
};

module.exports = {
  validateUpdateUser
};
