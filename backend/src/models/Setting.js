/**
 * Setting Mongoose Schema
 * Stores dynamic backend configuration parameters.
 * Note: Never store passwords or secrets in this collection.
 */

const mongoose = require('mongoose');

const settingSchema = new mongoose.Schema(
  {
    key: {
      type: String,
      required: true,
      unique: true,
      index: true
    },
    value: {
      type: mongoose.Schema.Types.Mixed,
      required: true
    },
    description: {
      type: String,
      default: ''
    },
    updatedAt: {
      type: Date,
      default: Date.now
    }
  },
  {
    timestamps: false,
    versionKey: false
  }
);

module.exports = mongoose.model('Setting', settingSchema);
