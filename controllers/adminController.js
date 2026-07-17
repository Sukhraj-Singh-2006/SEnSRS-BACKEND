const supabase = require("../db");

/**
 * GET ALL USERS
 */
exports.getUsers = async (req, res) => {
  console.log("GET /admin/users called");

  const { data, error } = await supabase.from("users").select("*");

  console.log("SUPABASE DATA:", data);

  if (error) {
    console.log(error);
    return res.status(500).json(error);
  }

  return res.json({
    success: true,
    users: data,
  });
};
/**
 * CREATE USER
 */
/**
 * CREATE USER
 */
const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");

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
      .select()
      .single();

    if (error) {
      return res.status(400).json(error);
    }

    res.status(201).json({
      success: true,
      user: data,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: err.message,
    });
  }
};

/**
 * UPDATE USER
 */
exports.updateUser = async (req, res) => {
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
    .select()
    .single();

  if (error) return res.status(400).json(error);

  res.json({
    success: true,
    user: data,
  });
};

/**
 * DELETE USER
 */
exports.deleteUser = async (req, res) => {
  const { id } = req.params;

  const { error } = await supabase.from("users").delete().eq("id", id);

  if (error) return res.status(400).json(error);

  res.json({
    success: true,
  });
};
