const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const config = require('../config/env');
const User = require('../models/User');
const logger = require('../utils/logger');

async function seedAdmin() {
  try {
    await mongoose.connect(config.mongodbUri);
    logger.info(`Connected to MongoDB for admin seeding: ${config.mongodbUri}`);

    const existingAdmin = await User.findOne({ role: 'ADMIN' });
    if (existingAdmin) {
      logger.info(`Admin user already exists (${existingAdmin.email}). Skipping seed.`);
      process.exit(0);
    }

    const passwordHash = await bcrypt.hash(config.adminPassword, 10);
    const adminUser = await User.create({
      username: config.adminUsername,
      email: config.adminEmail.toLowerCase(),
      passwordHash,
      role: 'ADMIN',
      isActive: true
    });

    logger.info(`[SUCCESS] Admin user seeded successfully! Email: ${adminUser.email}, Role: ${adminUser.role}`);
    process.exit(0);
  } catch (err) {
    logger.error('Error seeding admin user:', err.message);
    process.exit(1);
  }
}

seedAdmin();
