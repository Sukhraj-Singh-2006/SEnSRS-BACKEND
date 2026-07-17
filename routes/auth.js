// routes/auth.js
const express = require("express");
const router = express.Router();
const authController = require("../controllers/authController");
const { protect } = require("../middleware/authMiddleware");
const { restrictTo } = require("../middleware/roleMiddleware");
const { ROLES } = require("../constants/roles");

// Public routes - no authentication needed
router.post("/register", authController.register);
router.post("/login", authController.login);
router.post("/login/2fa/setup", authController.completeTwoFactorSetup);
router.post("/login/2fa", authController.verifyTwoFactorLogin);
router.post("/admin-login", authController.adminLogin);
router.post("/forgot-password", authController.forgotPassword);
router.post("/reset-password", authController.resetPassword);

// Protected routes - authentication needed
router.get("/me", protect, authController.me);
router.get("/dashboards", protect, authController.getDashboards);
router.post("/logout", protect, authController.logout);

// Note: Admin routes should be in a separate file like routes/admin.js
// This keeps auth routes clean and focused on authentication

module.exports = router;
