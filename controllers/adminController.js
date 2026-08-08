const supabase = require("../db");
const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");

/**
 * GET ALL USERS
 */
exports.getUsers = async (req, res) => {
  try {
    console.log("GET /admin/users called");

    const { data, error } = await supabase
      .from("users")
      .select("id,name,email,role,state,is_active,created_at,updated_at");

    if (error) {
      console.error("Failed to fetch users:", error.message);

      return res.status(500).json({
        success: false,
        message: "Failed to fetch users",
      });
    }

    return res.json({
      success: true,
      users: data,
    });
  } catch (err) {
    console.error("Get users error:", err.message);

    return res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
};

/**
 * CREATE USER
 */
exports.createUser = async (req, res) => {
  try {
    const { name, email, password, role, state, is_active } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const { data, error } = await supabase
      .from("users")
      .insert([
        {
          id: uuidv4(),
          name,
          email,
          password: hashedPassword,
          role,
          state,
          is_active,
        },
      ])
      .select("id,name,email,role,state,is_active,created_at,updated_at")
      .single();

    if (error) {
      console.error("Failed to create user:", error.message);

      return res.status(400).json({
        success: false,
        message: "Failed to create user",
      });
    }

    return res.status(201).json({
      success: true,
      user: data,
    });
  } catch (err) {
    console.error("Create user error:", err.message);

    return res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
};

/**
 * UPDATE USER
 */
exports.updateUser = async (req, res) => {
  try {
    const { id } = req.params;

    const { name, email, role, state, is_active } = req.body;

    const { data, error } = await supabase
      .from("users")
      .update({
        name,
        email,
        role,
        state,
        is_active,
      })
      .eq("id", id)
      .select("id,name,email,role,state,is_active,created_at,updated_at")
      .single();

    if (error) {
      console.error("Failed to update user:", error.message);

      return res.status(400).json({
        success: false,
        message: "Failed to update user",
      });
    }

    return res.json({
      success: true,
      user: data,
    });
  } catch (err) {
    console.error("Update user error:", err.message);

    return res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
};

/**
 * DELETE USER
 */
exports.deleteUser = async (req, res) => {
  try {
    const { id } = req.params;

    const { error } = await supabase.from("users").delete().eq("id", id);

    if (error) {
      console.error("Failed to delete user:", error.message);

      return res.status(400).json({
        success: false,
        message: "Failed to delete user",
      });
    }

    return res.json({
      success: true,
      message: "User deleted successfully",
    });
  } catch (err) {
    console.error("Delete user error:", err.message);

    return res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
};
