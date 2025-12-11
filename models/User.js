// models/User.js
const mongoose = require('mongoose');
const { ROLES, DEFAULT_ROLE, VALID_ROLES } = require('../constants/roles');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Name is required'],
    trim: true
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: 6
  },
  role: {
    type: String,
    enum: VALID_ROLES, // Only allow valid roles
    default: DEFAULT_ROLE,
    required: true
  },
  // Keep state for future if needed, or remove it
  state: {
    type: String,
    default: '',
    trim: true
  },
  // Additional fields for future flexibility
  isActive: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: {
    type: Date
  }
}, {
  timestamps: true
});

// Remove password from JSON responses
userSchema.set('toJSON', {
  transform: function(doc, ret) {
    delete ret.password;
    delete ret.__v;
    return ret;
  }
});

module.exports = mongoose.model('User', userSchema);