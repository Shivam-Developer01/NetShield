const User = require('../models/User');
const { logAuditEvent } = require('../utils/auditLogger');

const getUsers = async (req, res, next) => {
  try {
    const page = parseInt(req.query.page || '1', 10);
    const limit = parseInt(req.query.limit || '20', 10);
    const skip = (page - 1) * limit;

    const query = {};
    if (req.query.role && req.query.role !== 'all') query.role = req.query.role;
    if (req.query.isActive !== undefined && req.query.isActive !== 'all') {
      query.isActive = req.query.isActive === 'true';
    }

    const [users, total] = await Promise.all([
      User.find(query).sort({ createdAt: -1 }).skip(skip).limit(limit),
      User.countDocuments(query)
    ]);

    return res.status(200).json({
      success: true,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit) || 1
      },
      data: users
    });
  } catch (error) {
    next(error);
  }
};

const getUserById = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'NOT_FOUND',
          message: `User with ID '${req.params.id}' not found.`
        }
      });
    }

    return res.status(200).json({
      success: true,
      data: user
    });
  } catch (error) {
    next(error);
  }
};

const updateUser = async (req, res, next) => {
  try {
    const { id } = req.params;
    const { username, email, role, isActive } = req.body;

    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'NOT_FOUND',
          message: `User with ID '${id}' not found.`
        }
      });
    }

    // Safeguard: Prevent removing or deactivating the last active ADMIN user
    if ((role && role !== 'ADMIN') || (isActive === false)) {
      if (user.role === 'ADMIN') {
        const activeAdminCount = await User.countDocuments({ role: 'ADMIN', isActive: true });
        if (activeAdminCount <= 1) {
          logAuditEvent('ADMIN_ACTION_REJECTED', { targetUserId: id, details: { reason: 'Last admin safeguard triggered' }, success: false }, req);
          return res.status(400).json({
            success: false,
            error: {
              code: 'LAST_ADMIN_PROTECTION',
              message: 'Cannot demote or deactivate the last active ADMIN user.'
            }
          });
        }
      }
    }

    const previousRole = user.role;
    const previousStatus = user.isActive;

    if (username) user.username = username;
    if (email) user.email = email.toLowerCase();
    if (role) user.role = role;
    if (isActive !== undefined) user.isActive = isActive;

    await user.save();

    // Audit logs
    if (role && role !== previousRole) {
      logAuditEvent('ROLE_CHANGED', { targetUserId: user._id, email: user.email, previousRole, newRole: role }, req);
    }
    if (isActive !== undefined && isActive !== previousStatus) {
      logAuditEvent(isActive ? 'USER_ACTIVATED' : 'USER_DEACTIVATED', { targetUserId: user._id, email: user.email }, req);
    }

    return res.status(200).json({
      success: true,
      message: 'User updated successfully.',
      data: user
    });
  } catch (error) {
    next(error);
  }
};

const deleteUser = async (req, res, next) => {
  try {
    const { id } = req.params;

    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'NOT_FOUND',
          message: `User with ID '${id}' not found.`
        }
      });
    }

    if (user.role === 'ADMIN') {
      const activeAdminCount = await User.countDocuments({ role: 'ADMIN', isActive: true });
      if (activeAdminCount <= 1) {
        logAuditEvent('ADMIN_ACTION_REJECTED', { targetUserId: id, details: { reason: 'Last admin safeguard triggered on delete' }, success: false }, req);
        return res.status(400).json({
          success: false,
          error: {
            code: 'LAST_ADMIN_PROTECTION',
            message: 'Cannot delete the last active ADMIN user.'
          }
        });
      }
    }

    await User.findByIdAndDelete(id);

    logAuditEvent('USER_DELETED', { targetUserId: user._id, email: user.email }, req);

    return res.status(200).json({
      success: true,
      message: 'User deleted successfully.'
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  getUsers,
  getUserById,
  updateUser,
  deleteUser
};
