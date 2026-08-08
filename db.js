const { createClient } = require("@supabase/supabase-js");

require("dotenv").config();

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
);

async function testConnection() {
  const { error } = await supabase.from("users").select("id").limit(1);

  if (error) {
    console.error("❌ Supabase connection check failed:", error.message);
  } else {
    console.log("✅ Supabase Connected");
  }
}

testConnection();

module.exports = supabase;
