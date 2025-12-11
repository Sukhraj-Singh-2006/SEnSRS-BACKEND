// middleware/authMiddleware.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');

exports.protect = async (req, res, next) => {
  try {
    let token;

    // 1) prefer cookie
    if (req.cookies && req.cookies.token) {
      token = req.cookies.token;
    }

    // 2) fallback to header
    if (!token && req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      console.warn('protect: no token found. req.cookies=', req.cookies, 'authHeader=', req.headers.authorization?.slice?.(0,50));
      return res.status(401).json({ message: 'Not authorized: token missing' });
    }

    // verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      console.warn('protect: jwt.verify failed:', err && err.message);
      // explicit reasons for easier debugging
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ message: 'Not authorized: token expired' });
      }
      return res.status(401).json({ message: 'Not authorized: token invalid' });
    }

    // Option: re-fetch user from DB to ensure user still exists and get fresh fields
    if (process.env.PROTECT_REFETCH_USER === 'true') {
      const user = await User.findById(decoded.id).select('-password');
      if (!user) {
        return res.status(401).json({ message: 'Not authorized: user no longer exists' });
      }
      req.user = {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        role: user.role,
        state: user.state,
      };
    } else {
      // attach minimal info from token (fast)
      req.user = {
        id: decoded.id,
        role: decoded.role,
        state: decoded.state,
      };
    }

    next();
  } catch (err) {
    console.error('protect middleware unexpected error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
};

exports.authorize = (...allowedRoles) => (req, res, next) => {
  if (!req.user || !req.user.role) return res.status(401).json({ message: 'Not authenticated' });

  const userRole = String(req.user.role).toLowerCase();
  const normalizedAllowed = allowedRoles.map(r => String(r).toLowerCase());

  if (!normalizedAllowed.includes(userRole)) {
    return res.status(403).json({ message: 'Forbidden: insufficient role' });
  }
  next();
};
