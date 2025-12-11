// constants/roles.js

/**
 * Define all application roles with their permissions/description
 * This makes it easy to add new roles in the future
 */
const ROLES = {
  ADMIN: 'admin',
  USER: 'user'
  // Future roles can be added here:
  // EDITOR: 'editor',
  // MANAGER: 'manager',
  // VIEWER: 'viewer',
  // etc.
};

/**
 * Default role for new users
 */
const DEFAULT_ROLE = ROLES.USER;

/**
 * All valid roles (for validation)
 */
const VALID_ROLES = Object.values(ROLES);

/**
 * Role hierarchy - which roles can do what
 * Higher index = more permissions
 */
const ROLE_HIERARCHY = [ROLES.USER, ROLES.ADMIN];

/**
 * Check if a role has permission over another role
 */
const hasPermission = (userRole, requiredRole) => {
  const userIndex = ROLE_HIERARCHY.indexOf(userRole);
  const requiredIndex = ROLE_HIERARCHY.indexOf(requiredRole);
  
  return userIndex >= requiredIndex && userIndex !== -1;
};

/**
 * Get all roles that are at or below a given role in hierarchy
 */
const getAvailableRoles = (forRole) => {
  const roleIndex = ROLE_HIERARCHY.indexOf(forRole);
  if (roleIndex === -1) return [];
  
  return ROLE_HIERARCHY.slice(0, roleIndex + 1);
};

module.exports = {
  ROLES,
  DEFAULT_ROLE,
  VALID_ROLES,
  ROLE_HIERARCHY,
  hasPermission,
  getAvailableRoles
};