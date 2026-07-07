const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { ROLES, DEFAULT_ROLE, VALID_ROLES } = require('../constants/roles');
const { generateSecret, generateURI, verifySync } = require('otplib');
const QRCode = require('qrcode');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

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
    secure,
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

    if (user.twoFactorEnabled) {
      const challengeToken = jwt.sign(
        { id: user._id.toString(), purpose: '2fa-login' },
        process.env.JWT_SECRET,
        { expiresIn: '5m' }
      );
      return res.json({ twoFactorRequired: true, challengeToken });
    }

    return finishLogin(res, user);

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

exports.verifyTwoFactorLogin = async (req, res) => {
  try {
    const { challengeToken, code } = req.body;
    if (!challengeToken || !code) return res.status(400).json({ message: 'Challenge token and code are required' });
    let challenge;
    try {
      challenge = jwt.verify(challengeToken, process.env.JWT_SECRET);
    } catch {
      return res.status(401).json({ message: 'Two-factor challenge expired or invalid' });
    }
    if (challenge.purpose !== '2fa-login') return res.status(401).json({ message: 'Invalid two-factor challenge' });
    const user = await User.findById(challenge.id).select('+twoFactorSecret');
    if (!user || !user.twoFactorEnabled || !isValidTotp(user.twoFactorSecret, code)) {
      return res.status(401).json({ message: 'Invalid authentication code' });
    }
    return finishLogin(res, user);
  } catch (err) {
    console.error('2FA login error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
};

exports.setupTwoFactor = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('+twoFactorPendingSecret');
    if (!user) return res.status(404).json({ message: 'User not found' });
    if (user.twoFactorEnabled) return res.status(409).json({ message: 'Two-factor authentication is already enabled' });
    const secret = generateSecret();
    user.twoFactorPendingSecret = encryptSecret(secret);
    await user.save();
    const otpauthUrl = generateURI({ issuer: process.env.TOTP_ISSUER || 'SEnSRS', label: user.email, secret });
    const qrCodeDataUrl = await QRCode.toDataURL(otpauthUrl, { width: 260, margin: 1 });
    return res.json({ secret, otpauthUrl, qrCodeDataUrl });
  } catch (err) {
    console.error('2FA setup error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
};

exports.enableTwoFactor = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('+twoFactorPendingSecret');
    if (!user) return res.status(404).json({ message: 'User not found' });
    if (!isValidTotp(user.twoFactorPendingSecret, req.body.code)) {
      return res.status(400).json({ message: 'Invalid authentication code' });
    }
    user.twoFactorSecret = user.twoFactorPendingSecret;
    user.twoFactorPendingSecret = undefined;
    user.twoFactorEnabled = true;
    await user.save();
    return res.json({ message: 'Two-factor authentication enabled', twoFactorEnabled: true });
  } catch (err) {
    console.error('2FA enable error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
};

exports.disableTwoFactor = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('+twoFactorSecret');
    if (!user) return res.status(404).json({ message: 'User not found' });
    const passwordMatches = await bcrypt.compare(req.body.password || '', user.password);
    if (!passwordMatches || !isValidTotp(user.twoFactorSecret, req.body.code)) {
      return res.status(401).json({ message: 'Password or authentication code is invalid' });
    }
    user.twoFactorEnabled = false;
    user.twoFactorSecret = undefined;
    user.twoFactorPendingSecret = undefined;
    await user.save();
    return res.json({ message: 'Two-factor authentication disabled', twoFactorEnabled: false });
  } catch (err) {
    console.error('2FA disable error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
};

const serializeUser = (user) => ({
  id: user._id, name: user.name, email: user.email, role: user.role,
  state: user.state, isActive: user.isActive,
  twoFactorEnabled: Boolean(user.twoFactorEnabled)
});

const encryptionKey = () => crypto.createHash('sha256')
  .update(process.env.TOTP_ENCRYPTION_KEY || process.env.JWT_SECRET || '')
  .digest();

const encryptSecret = (plainText) => {
  if (!process.env.TOTP_ENCRYPTION_KEY && !process.env.JWT_SECRET) {
    throw new Error('TOTP_ENCRYPTION_KEY or JWT_SECRET must be configured');
  }
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
  return ['v1', iv.toString('base64url'), cipher.getAuthTag().toString('base64url'), encrypted.toString('base64url')].join('.');
};

const decryptSecret = (value) => {
  if (!value?.startsWith('v1.')) return value;
  const [, iv, tag, encrypted] = value.split('.');
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), Buffer.from(iv, 'base64url'));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(encrypted, 'base64url')), decipher.final()]).toString('utf8');
};

const isValidTotp = (storedSecret, code) => {
  if (!storedSecret || !/^\d{6}$/.test(String(code || '').trim())) return false;
  return verifySync({ secret: decryptSecret(storedSecret), token: String(code).trim(), epochTolerance: 30 }).valid;
};

const finishLogin = async (res, user) => {
  user.lastLogin = new Date();
  await user.save();
  const token = signToken(user);
  res.cookie('token', token, buildCookieOptions());
  const body = { user: serializeUser(user) };
  if (process.env.SEND_TOKEN_IN_RESPONSE === 'true') body.token = token;
  return res.json(body);
};

exports.forgotPassword = async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!email) return res.status(400).json({ message: 'Email is required' });

    const user = await User.findOne({ email }).select('+passwordResetToken +passwordResetExpires');
    const genericMessage = 'If an account exists for that email, a password reset link has been sent.';
    if (!user) return res.json({ message: genericMessage });

    const resetToken = crypto.randomBytes(32).toString('hex');
    user.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    user.passwordResetExpires = new Date(Date.now() + 15 * 60 * 1000);
    await user.save();

    const frontendUrl = (process.env.FRONTEND_URL || 'http://localhost:3000').replace(/\/$/, '');
    const resetUrl = `${frontendUrl}/reset-password/?token=${resetToken}`;

    if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT || 587),
        secure: String(process.env.SMTP_SECURE).toLowerCase() === 'true',
        auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
      });
      await transporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: user.email,
        subject: 'Reset your SEnSRS password',
        text: `Use this link to reset your password. It expires in 15 minutes: ${resetUrl}`,
        html: `<p>We received a request to reset your SEnSRS password.</p><p><a href="${resetUrl}">Reset password</a></p><p>This link expires in 15 minutes. If you did not request this, you can ignore this email.</p>`
      });
      return res.json({ message: genericMessage });
    }

    if (process.env.NODE_ENV !== 'production') {
      return res.json({ message: genericMessage, developmentResetUrl: resetUrl });
    }
    console.error('Password reset email not sent: SMTP is not configured');
    return res.status(503).json({ message: 'Password reset email service is temporarily unavailable' });
  } catch (err) {
    console.error('Forgot password error:', err);
    return res.status(500).json({ message: 'Unable to process password reset request' });
  }
};

exports.resetPassword = async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password) return res.status(400).json({ message: 'Reset token and new password are required' });
    if (String(password).length < 8) return res.status(400).json({ message: 'Password must be at least 8 characters' });

    const tokenHash = crypto.createHash('sha256').update(String(token)).digest('hex');
    const user = await User.findOne({
      passwordResetToken: tokenHash,
      passwordResetExpires: { $gt: new Date() }
    }).select('+passwordResetToken +passwordResetExpires');
    if (!user) return res.status(400).json({ message: 'Reset link is invalid or has expired' });

    user.password = await bcrypt.hash(String(password), 12);
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();
    res.clearCookie('token', { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', path: '/' });
    return res.json({ message: 'Password reset successfully. You can now log in.' });
  } catch (err) {
    console.error('Reset password error:', err);
    return res.status(500).json({ message: 'Unable to reset password' });
  }
};
