const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
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
// ===========================
// LOGIN BRUTE-FORCE PROTECTION
// ===========================

const MAX_LOGIN_ATTEMPTS = 3;
const LOCKOUT_MINUTES = 10;

// Check whether the account is currently locked
function isAccountLocked(user) {
  if (!user.locked_until) {
    return false;
  }

  const lockedUntil = new Date(user.locked_until);
  const now = new Date();

  return lockedUntil > now;
}

// Record a failed login attempt
async function recordFailedLogin(user) {
  const attempts = (user.failed_login_attempts || 0) + 1;

  // Lock account after 5 failed attempts
  if (attempts >= MAX_LOGIN_ATTEMPTS) {
    const lockedUntil = new Date(
      Date.now() + LOCKOUT_MINUTES * 60 * 1000,
    ).toISOString();

    const { error } = await supabase
      .from("users")
      .update({
        failed_login_attempts: attempts,
        locked_until: lockedUntil,
      })
      .eq("id", user.id);

    if (error) {
      console.error("Failed to lock account:", error);
    }

    return {
      locked: true,
      attempts,
      lockedUntil,
    };
  }

  // Account not locked yet
  const { error } = await supabase
    .from("users")
    .update({
      failed_login_attempts: attempts,
    })
    .eq("id", user.id);

  if (error) {
    console.error("Failed to update failed login attempts:", error);
  }

  return {
    locked: false,
    attempts,
  };
}

// Reset login attempts after successful password verification
async function resetLoginAttempts(userId) {
  const { error } = await supabase
    .from("users")
    .update({
      failed_login_attempts: 0,
      locked_until: null,
    })
    .eq("id", userId);

  if (error) {
    console.error("Failed to reset login attempts:", error);
  }
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
    // ===========================
    // CHECK ACCOUNT LOCK
    // ===========================

    if (isAccountLocked(user)) {
      const lockedUntil = new Date(user.locked_until);

      const remainingMinutes = Math.ceil(
        (lockedUntil.getTime() - Date.now()) / 60000,
      );

      return res.status(429).json({
        message: `Too many failed login attempts. Please try again in ${remainingMinutes} minute(s).`,
      });
    }

    // ===========================
    // CHECK PASSWORD
    // ===========================

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      const result = await recordFailedLogin(user);

      if (result.locked) {
        return res.status(429).json({
          message:
            "Too many failed login attempts. Your account has been temporarily locked for 15 minutes.",
        });
      }

      const remainingAttempts = MAX_LOGIN_ATTEMPTS - result.attempts;

      return res.status(401).json({
        message: "Invalid credentials",
        remainingAttempts,
      });
    }

    // ===========================
    // PASSWORD CORRECT
    // ===========================

    // Reset failed login attempts
    await resetLoginAttempts(user.id);

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
  try {
    const { email } = req.body;

    // Validate email
    if (!email) {
      return res.status(400).json({
        message: "Email is required",
      });
    }

    // Normalize email
    const normalizedEmail = email.trim().toLowerCase();

    // Find user
    const { data: user, error } = await supabase
      .from("users")
      .select("id, email, name")
      .eq("email", normalizedEmail)
      .maybeSingle();

    if (error) {
      console.error("Forgot password lookup error:", error);

      return res.status(500).json({
        message: "Unable to process password reset request",
      });
    }

    /*
     * Do not reveal whether the email exists.
     */
    if (!user) {
      return res.json({
        message:
          "If an account exists for this email, a password reset link has been sent.",
      });
    }

    // Generate secure random reset token
    const resetToken = crypto.randomBytes(32).toString("hex");

    // Hash token before storing it
    const tokenHash = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");

    // Token expires after 15 minutes
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    // Save hashed token and expiry
    const { error: updateError } = await supabase
      .from("users")
      .update({
        password_reset_token: tokenHash,
        password_reset_expires: expiresAt,
      })
      .eq("id", user.id);

    if (updateError) {
      console.error("Password reset token database error:", updateError);

      return res.status(500).json({
        message: "Unable to create password reset request",
      });
    }

    // Frontend URL
    const frontendUrl = process.env.FRONTEND_URL || "http://localhost:3000";

    // Create reset URL
    const resetUrl = `${frontendUrl}/reset-password?token=${encodeURIComponent(
      resetToken,
    )}`;

    // ==============================
    // SEND EMAIL USING BREVO
    // ==============================

    const brevoApiKey = process.env.BREVO_API_KEY;
    const senderEmail = process.env.BREVO_SENDER_EMAIL;
    const senderName = process.env.BREVO_SENDER_NAME || "SEnSRS";

    if (!brevoApiKey || !senderEmail) {
      console.error("Brevo configuration is missing.");

      return res.status(500).json({
        message: "Email service is not configured",
      });
    }

    const brevoResponse = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: {
        accept: "application/json",
        "api-key": brevoApiKey,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        sender: {
          name: senderName,
          email: senderEmail,
        },

        to: [
          {
            email: user.email,
            name: user.name || user.email,
          },
        ],

        subject: "SEnSRS Password Reset",

        htmlContent: `
            <!DOCTYPE html>
            <html>
              <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <h2 style="color: #1f5d48;">
                  Reset your SEnSRS password
                </h2>

                <p>Hello ${user.name || "User"},</p>

                <p>
                  We received a request to reset your SEnSRS account password.
                </p>

                <p>
                  Click the button below to choose a new password:
                </p>

                <p>
                  <a
                    href="${resetUrl}"
                    style="
                      display: inline-block;
                      padding: 12px 24px;
                      background-color: #28a745;
                      color: white;
                      text-decoration: none;
                      border-radius: 6px;
                      font-weight: bold;
                    "
                  >
                    Reset Password
                  </a>
                </p>

                <p>
                  This link will expire in <strong>15 minutes</strong>.
                </p>

                <p>
                  If you did not request a password reset, you can safely
                  ignore this email.
                </p>

                <p>
                  Regards,<br />
                  SEnSRS Team
                </p>
              </body>
            </html>
          `,
      }),
    });

    if (!brevoResponse.ok) {
      const brevoError = await brevoResponse.text();

      console.error(
        "Brevo email sending failed:",
        brevoResponse.status,
        brevoError,
      );

      return res.status(500).json({
        message: "Unable to send password reset email",
      });
    }

    const brevoResult = await brevoResponse.json();

    console.log(
      "Password reset email sent successfully:",
      brevoResult.messageId || "accepted",
    );

    // ==============================
    // SUCCESS
    // ==============================

    return res.json({
      message:
        "If an account exists for this email, a password reset link has been sent.",
    });
  } catch (err) {
    console.error("Forgot password error:", err);

    return res.status(500).json({
      message: "Server Error",
    });
  }
};

exports.resetPassword = async (req, res) => {
  try {
    const { token, password } = req.body;

    // Validate input
    if (!token || !password) {
      return res.status(400).json({
        message: "Reset token and new password are required",
      });
    }

    // Basic password validation
    if (password.length < 8) {
      return res.status(400).json({
        message: "Password must be at least 8 characters long",
      });
    }

    // Hash token received from reset URL
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    // Find user using hashed token
    const { data: user, error } = await supabase
      .from("users")
      .select("id, email, name, password_reset_token, password_reset_expires")
      .eq("password_reset_token", tokenHash)
      .maybeSingle();

    if (error) {
      console.error("Reset password lookup error:", error);

      return res.status(500).json({
        message: "Unable to process password reset",
      });
    }

    // Invalid token
    if (!user) {
      return res.status(400).json({
        message: "Invalid or expired password reset link",
      });
    }

    // Check token expiry
    if (
      !user.password_reset_expires ||
      new Date(user.password_reset_expires) < new Date()
    ) {
      return res.status(400).json({
        message: "Invalid or expired password reset link",
      });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update password and invalidate reset token
    const { error: updateError } = await supabase
      .from("users")
      .update({
        password: hashedPassword,

        // Token can only be used once
        password_reset_token: null,
        password_reset_expires: null,
      })
      .eq("id", user.id);

    if (updateError) {
      console.error("Password update error:", updateError);

      return res.status(500).json({
        message: "Unable to reset password",
      });
    }

    return res.json({
      message:
        "Password reset successfully. You can now log in with your new password.",
    });
  } catch (err) {
    console.error("Reset password error:", err);

    return res.status(500).json({
      message: "Server Error",
    });
  }
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
