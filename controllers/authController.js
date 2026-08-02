const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const supabase = require("../db");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const { DEFAULT_ROLE, VALID_ROLES } = require("../constants/roles");

const signToken = (user) => {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRES_IN || "7d",
    },
  );
};

function buildCookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: "/",
  };
}

// ---------- TEMPORARY ----------

exports.register = async (req, res) => {
  try {
    const { name, email, password, role = DEFAULT_ROLE, state } = req.body;

    // Validate required fields
    if (!name || !email || !password) {
      return res.status(400).json({
        message: "Name, email and password are required",
      });
    }

    // Validate role
    if (!VALID_ROLES.includes(role)) {
      return res.status(400).json({
        message: "Invalid role",
      });
    }

    // Check if email already exists
    const { data: existingUser, error: checkError } = await supabase
      .from("users")
      .select("id")
      .eq("email", email)
      .maybeSingle();

    if (checkError) {
      return res.status(500).json({
        message: checkError.message,
      });
    }

    if (existingUser) {
      return res.status(400).json({
        message: "Email already exists",
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user
    const { data: user, error: insertError } = await supabase
      .from("users")
      .insert([
        {
          name,
          email,
          password: hashedPassword,
          role,
          state,
        },
      ])
      .select()
      .single();

    if (insertError) {
      return res.status(500).json({
        message: insertError.message,
      });
    }

    // Generate JWT
    return res.status(201).json({
      message: "Registration successful. Please login to continue.",
    });
  } catch (err) {
    console.error(err);

    return res.status(500).json({
      message: "Server Error",
    });
  }
};
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required",
      });
    }

    // Find user
    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("email", email)
      .maybeSingle();

    if (error) {
      return res.status(500).json({
        message: error.message,
      });
    }

    if (!user) {
      return res.status(401).json({
        message: "Invalid credentials",
      });
    }

    // Check password
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({
        message: "Invalid credentials",
      });
    }
    if (user.is_active === false) {
      return res.status(403).json({
        message: "Your account is inactive. Please contact an administrator.",
      });
    }

    // ===========================
    // FIRST LOGIN (NO 2FA SETUP)
    // ===========================
    if (!user.two_factor_secret) {
      let secret;

      // Reuse existing pending secret if available
      if (user.two_factor_pending_secret) {
        secret = {
          base32: user.two_factor_pending_secret,
          otpauth_url: speakeasy.otpauthURL({
            secret: user.two_factor_pending_secret,
            label: `SEnSRS (${user.email})`,
            issuer: "SEnSRS",
            encoding: "base32",
          }),
        };
      } else {
        // Generate new secret
        secret = speakeasy.generateSecret({
          name: `SEnSRS (${user.email})`,
        });

        const { error: updateError } = await supabase
          .from("users")
          .update({
            two_factor_pending_secret: secret.base32,
          })
          .eq("id", user.id);

        if (updateError) {
          return res.status(500).json({
            message: updateError.message,
          });
        }
      }

      const qrCode = await QRCode.toDataURL(secret.otpauth_url);

      return res.json({
        requires2FASetup: true,
        userId: user.id,
        name: user.name,
        qrCode,
      });
    }

    // ===========================
    // EXISTING USER
    // ===========================
    return res.json({
      requires2FA: true,
      userId: user.id,
      name: user.name,
    });
  } catch (err) {
    console.error(err);

    return res.status(500).json({
      message: "Server Error",
    });
  }
};
exports.adminLogin = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required",
      });
    }

    // Find user
    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("email", email)
      .maybeSingle();

    if (error) {
      return res.status(500).json({
        message: error.message,
      });
    }

    if (!user) {
      return res.status(401).json({
        message: "Invalid credentials",
      });
    }

    // Check password
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({
        message: "Invalid credentials",
      });
    }
    if (user.is_active === false) {
      return res.status(403).json({
        message: "Your account is inactive. Please contact an administrator.",
      });
    }
    // ✅ Only admin can login here
    if (user.role !== "admin") {
      return res.status(403).json({
        message: "Access denied. Admins only.",
      });
    }

    // ===========================
    // FIRST LOGIN (NO 2FA SETUP)
    // ===========================
    if (!user.two_factor_secret) {
      let secret;

      // Reuse existing pending secret if available
      if (user.two_factor_pending_secret) {
        secret = {
          base32: user.two_factor_pending_secret,
          otpauth_url: speakeasy.otpauthURL({
            secret: user.two_factor_pending_secret,
            label: `SEnSRS (${user.email})`,
            issuer: "SEnSRS",
            encoding: "base32",
          }),
        };
      } else {
        // Generate new secret
        secret = speakeasy.generateSecret({
          name: `SEnSRS (${user.email})`,
        });

        const { error: updateError } = await supabase
          .from("users")
          .update({
            two_factor_pending_secret: secret.base32,
          })
          .eq("id", user.id);

        if (updateError) {
          return res.status(500).json({
            message: updateError.message,
          });
        }
      }

      const qrCode = await QRCode.toDataURL(secret.otpauth_url);

      return res.json({
        requires2FASetup: true,
        userId: user.id,
        name: user.name,
        qrCode,
      });
    }

    // ===========================
    // EXISTING USER
    // ===========================
    return res.json({
      requires2FA: true,
      userId: user.id,
      name: user.name,
    });
  } catch (err) {
    console.error(err);

    return res.status(500).json({
      message: "Server Error",
    });
  }
};
exports.logout = async (req, res) => {
  try {
    res.clearCookie("token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
    });

    return res.json({
      message: "Logged out successfully",
    });
  } catch (err) {
    console.error(err);

    return res.status(500).json({
      message: "Server Error",
    });
  }
};

exports.me = async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("id,name,email,role,state,is_active")
      .eq("id", req.user.id)
      .single();

    if (error || !user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    return res.json({
      user,
    });
  } catch (err) {
    console.error(err);

    return res.status(500).json({
      message: "Server Error",
    });
  }
};

exports.getDashboards = async (req, res) => {
  res.json({ message: "Dashboard coming next" });
};

exports.forgotPassword = async (req, res) => {
  res.json({ message: "Forgot Password coming next" });
};

exports.resetPassword = async (req, res) => {
  res.json({ message: "Reset Password coming next" });
};

exports.completeTwoFactorSetup = async (req, res) => {
  try {
    const { userId, token } = req.body;

    if (!userId || !token) {
      return res.status(400).json({
        message: "User ID and verification code are required",
      });
    }

    // Find user
    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("id", userId)
      .single();

    if (error || !user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    if (user.is_active === false) {
      return res.status(403).json({
        message: "Your account is inactive. Please contact an administrator.",
      });
    }

    if (!user.two_factor_pending_secret) {
      return res.status(400).json({
        message: "No pending 2FA setup found",
      });
    }

    // Verify Microsoft Authenticator code
    const verified = speakeasy.totp.verify({
      secret: user.two_factor_pending_secret,
      encoding: "base32",
      token,
      window: 1,
    });

    if (!verified) {
      return res.status(400).json({
        message: "Invalid verification code",
      });
    }

    // Save secret permanently
    const { error: updateError } = await supabase
      .from("users")
      .update({
        two_factor_secret: user.two_factor_pending_secret,
        two_factor_pending_secret: null,
        two_factor_enabled: true,
      })
      .eq("id", user.id);

    if (updateError) {
      return res.status(500).json({
        message: updateError.message,
      });
    }

    // Create JWT
    const jwtToken = signToken(user);

    // Set cookie
    res.cookie("token", jwtToken, buildCookieOptions());

    return res.json({
      message: "2FA setup completed successfully",
      token: jwtToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        state: user.state,
        isActive: user.is_active,
      },
    });
  } catch (err) {
    console.error(err);

    return res.status(500).json({
      message: "Server Error",
    });
  }
};
exports.verifyTwoFactorLogin = async (req, res) => {
  try {
    const { userId, token } = req.body;

    if (!userId || !token) {
      return res.status(400).json({
        message: "User ID and verification code are required",
      });
    }

    // Find user
    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("id", userId)
      .single();

    if (error || !user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    if (user.is_active === false) {
      return res.status(403).json({
        message: "Your account is inactive. Please contact an administrator.",
      });
    }

    if (!user.two_factor_secret) {
      return res.status(400).json({
        message: "Two-factor authentication is not configured",
      });
    }

    // Verify TOTP
    const verified = speakeasy.totp.verify({
      secret: user.two_factor_secret,
      encoding: "base32",
      token,
      window: 1,
    });

    if (!verified) {
      return res.status(401).json({
        message: "Invalid verification code",
      });
    }


    // Create JWT
    const jwtToken = signToken(user);

    // Set Cookie
    res.cookie("token", jwtToken, buildCookieOptions());

    return res.json({
      message: "Login successful",
      token: jwtToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        state: user.state,
        isActive: user.is_active,
      },
    });
  } catch (err) {
    console.error(err);

    return res.status(500).json({
      message: "Server Error",
    });
  }
};
