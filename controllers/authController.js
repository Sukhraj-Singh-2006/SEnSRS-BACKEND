const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { ROLES, DEFAULT_ROLE, VALID_ROLES } = require('../constants/roles');

/**
 * Parse duration strings like:
 *  '7d' -> days, '1h' -> hours, '30m' -> minutes, '60s' -> seconds
 *  fallback: treat number as milliseconds
 */
function parseDurationToMs(dur) {
  if (!dur) return 7 * 24 * 60 * 60 * 1000; // default 7 days
  if (typeof dur === 'number') return dur;
  const s = String(dur).trim().toLowerCase();
  const last = s[s.length - 1];
  const num = Number(s.slice(0, -1));
  if (!Number.isNaN(num) && (last === 'd' || last === 'h' || last === 'm' || last === 's')) {
    if (last === 'd') return num * 24 * 60 * 60 * 1000;
    if (last === 'h') return num * 60 * 60 * 1000;
    if (last === 'm') return num * 60 * 1000;
    if (last === 's') return num * 1000;
  }
  // if not with suffix, maybe it's seconds or milliseconds: try parse as ms/seconds
  const parsed = Number(s);
  if (!Number.isNaN(parsed)) {
    // assume seconds if reasonable (< 1e7), else milliseconds
    return parsed < 1e7 ? parsed * 1000 : parsed;
  }
  // fallback 7 days
  return 7 * 24 * 60 * 60 * 1000;
}

const signToken = (user) => {
  // Include role in token for authorization checks
  return jwt.sign(
    { 
      id: user._id.toString(), 
      role: user.role,
      email: user.email // Optional: include email for display purposes
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
  );
};

/**
 * Build cookie options used for setting and clearing the auth cookie.
 * Keep consistent between set and clear.
 */
function buildCookieOptions() {
  const secure = process.env.NODE_ENV === 'production';
  const maxAge = parseDurationToMs(process.env.JWT_EXPIRES_IN || '7d');
  return {
    httpOnly: true,
    secure : false,  // Set to false for local development, true in production
    sameSite: 'lax',
    maxAge,
    path: '/', // cookie available site-wide
  };
}

/**
 * Try to extract and verify token either from req.user (set by protect middleware)
 * or from cookies. Returns decoded token payload or null.
 */
async function getDecodedTokenFromReq(req) {
  if (req && req.user && req.user.id) {
    // protect middleware already decoded token; return a minimal shape
    return { id: req.user.id, role: req.user.role, state: req.user.state };
  }

  // try cookie
  const token = (req && req.cookies && req.cookies.token) || (req && req.headers && req.headers.authorization && req.headers.authorization.split(' ')[1]);
  if (!token) return null;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return decoded;
  } catch (err) {
    // invalid or expired token
    return null;
  }
}

/**
 * Register a new user
 */
exports.register = async (req, res) => {
  try {
    const { name, email, password, role = DEFAULT_ROLE, state } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    // Validate role if provided
    if (role && !VALID_ROLES.includes(role)) {
      return res.status(400).json({ 
        message: 'Invalid role',
        validRoles: VALID_ROLES 
      });
    }

    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ message: 'Email already exists' });

    const hashed = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      password: hashed,
      role,
      state
    });

    const token = signToken(user);

    // set cookie (httpOnly)
    res.cookie('token', token, buildCookieOptions());

    // prepare safe user object to return
    const safeUser = {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      state: user.state,
      isActive: user.isActive
    };

    if (process.env.SEND_TOKEN_IN_RESPONSE === 'true') {
      return res.status(201).json({ token, user: safeUser });
    }

    return res.status(201).json({ user: safeUser });

  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
};

/**
 * Login existing user
 */
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Missing credentials' });

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    // Check if user is active
    if (user.isActive === false) {
      return res.status(401).json({ message: 'Account is deactivated' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: 'Invalid credentials' });

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    const token = signToken(user);

    // set cookie (httpOnly)
    res.cookie('token', token, buildCookieOptions());

    const safeUser = {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      state: user.state,
      isActive: user.isActive
    };

    if (process.env.SEND_TOKEN_IN_RESPONSE === 'true') {
      return res.json({ token, user: safeUser });
    }

    return res.json({ user: safeUser });

  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
};

/**
 * Logout current user (clear cookie)
 */
exports.logout = async (req, res) => {
  try {
    // Clear the cookie using same flags (path + secure + sameSite)
    res.clearCookie('token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
    });
    return res.json({ message: 'Logged out' });
  } catch (err) {
    console.error('Logout error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
};

/**
 * Return the authenticated user's basic information.
 * This assumes protect middleware has already attached req.user
 */
exports.me = async (req, res) => {
  try {
    // prefer req.user.id from protect middleware (fast)
    const userId = req.user && req.user.id;
    if (!userId) {
      return res.status(401).json({ message: 'Not authenticated' });
    }

    // fetch fresh user from DB (do not return password)
    const user = await User.findById(userId).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Convert to plain object and ensure _id becomes id
    const userObj = user.toObject();
    const { _id, password, ...userData } = userObj;
    
    return res.json({ 
      user: {
        id: _id,
        ...userData
      }
    });
  } catch (error) {
    console.error('me controller error:', error);
    return res.status(500).json({ message: 'Server error' });
  }
};

/**
 * Return dashboard links based on user's role / state.
 * Expects protect middleware to attach req.user (but also tolerant if not present).
 */
exports.getDashboards = async (req, res) => {
  try {
    const userId = req.user && req.user.id;
    if (!userId) {
      return res.status(401).json({ message: 'Not authenticated' });
    }

    // Fetch fresh user to get current role and state
    const user = await User.findById(userId).select('role state');
    if (!user) return res.status(404).json({ message: 'User not found' });

    const { role, state } = user;
    let links = [];

    // Admin gets all dashboards
    if (role === ROLES.ADMIN) {
      links.push(
        { key: 'admin_dashboard', title: 'Admin Dashboard', path: '/admin' },
        { key: 'sensrs_internal', title: 'SEnSRS Dashboard (Internal)', path: '/dashboards/sensrs' },
        { key: 'punjab', title: 'Punjab Dashboard', path: '/dashboards/punjab' },
        { key: 'user_management', title: 'User Management', path: '/admin/users' }
      );
    }

    // Regular users get basic access
    if (role === ROLES.USER) {
      links.push(
        { key: 'user_dashboard', title: 'My Dashboard', path: '/dashboard' }
      );
      
      // State-specific dashboards for users
      if (state === 'punjab') {
        links.push({ 
          key: 'punjab_state', 
          title: 'Punjab State Dashboard', 
          path: '/dashboards/punjab' 
        });
      }
    }

    // You mentioned having 'internal' role earlier - keep it if needed
    if (role === 'internal') {
      links.push({
        key: 'sensrs_internal',
        title: 'SEnSRS Dashboard (Internal)',
        path: '/dashboards/sensrs'
      });
    }

    return res.json({ 
      links,
      userRole: role,
      userState: state
    });

  } catch (err) {
    console.error('getDashboards error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
};