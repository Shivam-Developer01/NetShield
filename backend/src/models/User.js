const mongoose = require('mongoose');

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, 'Username is required'],
      trim: true,
      minlength: [2, 'Username must be at least 2 characters']
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
      index: true
    },
    passwordHash: {
      type: String,
      required: [true, 'Password hash is required'],
      select: false // Password hash is never returned in default queries
    },
    role: {
      type: String,
      enum: {
        values: ['ADMIN', 'ANALYST', 'VIEWER'],
        message: 'Role must be one of: ADMIN, ANALYST, VIEWER'
      },
      default: 'VIEWER',
      index: true
    },
    isActive: {
      type: Boolean,
      default: true,
      index: true
    },
    lastLoginAt: {
      type: Date,
      default: null
    }
  },
  {
    timestamps: true
  }
);

// Method to remove passwordHash if user object is converted to JSON
userSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.passwordHash;
  return obj;
};

module.exports = mongoose.model('User', userSchema);
