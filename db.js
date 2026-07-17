const { createClient } = require("@supabase/supabase-js");
require("dotenv").config();

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
);

async function testConnection() {
  const { data, error } = await supabase.from("users").select("*");

  if (error) {
    console.log(error);
  } else {
    console.log("✅ Supabase Connected");
    console.log(data);
  }
}

testConnection();

module.exports = supabase;
