// middleware/roleMiddleware.js
const { hasPermission } = require('../constants/roles');

/**
 * Restrict access to specific roles
 * Usage: router.get('/admin', restrictTo('admin'), adminController.dashboard)
 */
exports.restrictTo = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(401).json({ message: 'Not authenticated' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ 
        message: 'You do not have permission to access this resource',
        requiredRoles: allowedRoles,
        yourRole: req.user.role
      });
    }

    next();
  };
};

/**
 * Check if user has permission over a specific role
 * Usage: canAssignRole('admin') - returns true if user can assign admin role
 */
exports.canAssignRole = (targetRole) => {
  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(401).json({ message: 'Not authenticated' });
    }

    if (!hasPermission(req.user.role, targetRole)) {
      return res.status(403).json({ 
        message: `You cannot assign ${targetRole} role`,
        requiredPermission: targetRole,
        yourRole: req.user.role
      });
    }

    next();
  };
};