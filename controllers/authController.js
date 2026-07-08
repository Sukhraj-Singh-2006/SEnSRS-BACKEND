const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const supabase = require("../db");
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
    const token = signToken(user);

    // Set cookie
    res.cookie("token", token, buildCookieOptions());

    // Return response
    return res.status(201).json({
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

    // Create JWT
    const token = signToken(user);

    // Set cookie
    res.cookie("token", token, buildCookieOptions());

    return res.json({
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

exports.setupTwoFactor = async (req, res) => {
  res.json({ message: "Setup 2FA coming next" });
};

exports.enableTwoFactor = async (req, res) => {
  res.json({ message: "Enable 2FA coming next" });
};

exports.disableTwoFactor = async (req, res) => {
  res.json({ message: "Disable 2FA coming next" });
};

exports.verifyTwoFactorLogin = async (req, res) => {
  res.json({ message: "Verify 2FA coming next" });
};
