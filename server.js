const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const cookieParser = require("cookie-parser");

dotenv.config();

require("./db");

const adminRoutes = require("./routes/admin");
const authRoutes = require("./routes/auth");

const app = express();

// Trust proxy (for production)
app.set("trust proxy", 1);

// ======================
// CORS Configuration
// ======================
const whitelist = [
  "http://localhost:3000",
  "https://sensrs.com",
  "https://alice.sensrs.com",
];

const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (Postman, curl, mobile apps)
    if (!origin) return callback(null, true);

    if (whitelist.includes(origin)) {
      return callback(null, true);
    }

    console.log("❌ Blocked CORS Origin:", origin);
    callback(new Error("Not allowed by CORS"));
  },

  credentials: true,

  methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],

  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "Accept",
    "X-Requested-With",
  ],
};

// ======================
// Middleware
// ======================

app.use(cors(corsOptions));

app.options("*", cors(corsOptions));

app.use(express.json());

app.use(express.urlencoded({ extended: true }));

app.use(cookieParser());

// Debug middleware (remove later)
app.use((req, res, next) => {
  console.log(
    `${req.method} ${req.originalUrl} | Origin: ${req.headers.origin}`,
  );
  next();
});

// ======================
// Routes
// ======================

app.use("/api/auth", authRoutes);

app.use("/api/admin", adminRoutes);

app.get("/", (req, res) => {
  res.send("SEnSRS backend running");
});

// ======================
// Error Handler
// ======================

app.use((err, req, res, next) => {
  console.error(err.stack);

  res.status(500).json({
    success: false,
    message: err.message || "Internal Server Error",
  });
});

// ======================
// Start Server
// ======================

const PORT = process.env.PORT || 5001;

app.listen(PORT, () => {
  console.log(`🚀 Server started on port ${PORT}`);
});
