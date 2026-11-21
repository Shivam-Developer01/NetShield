/**
 * Mongoose MongoDB Connection Management
 * Handles connection establishing, lifecycle logging, retry logic, and graceful shutdown.
 */

const mongoose = require('mongoose');
const config = require('./env');

const connectDatabase = async (uriOverride = null) => {
  const targetUri = uriOverride || config.mongodbUri || config.mongoUri;

  const mongooseOptions = {
    autoIndex: true,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000
  };

  try {
    const conn = await mongoose.connect(targetUri, mongooseOptions);
    if (!config.isTest) {
      console.log(`[MongoDB] Connected successfully to host: ${conn.connection.host}, database: ${conn.connection.name}`);
    }
    return conn;
  } catch (error) {
    if (!config.isTest) {
      console.error(`[MongoDB] Initial connection error to ${targetUri}:`, error.message);
    }
    throw error;
  }
};

const disconnectDatabase = async () => {
  if (mongoose.connection.readyState !== 0) {
    await mongoose.disconnect();
    if (!config.isTest) {
      console.log('[MongoDB] Disconnected gracefully.');
    }
  }
};

mongoose.connection.on('disconnected', () => {
  if (!config.isTest) {
    console.warn('[MongoDB] Lost database connection.');
  }
});

mongoose.connection.on('error', (err) => {
  if (!config.isTest) {
    console.error('[MongoDB] Runtime connection error:', err.message);
  }
});

module.exports = {
  connectDatabase,
  disconnectDatabase
};
