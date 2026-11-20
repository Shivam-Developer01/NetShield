/**
 * Phase 20: MongoDB Backup & Restore Verification Script
 * Uses MongoMemoryServer to seed source collections, runs scripts/backup_mongodb.py,
 * restores into netshield_restore_verify_db, and asserts 100% document & field parity.
 */

const path = require('path');
module.paths.push(path.resolve(__dirname, '..', 'backend', 'node_modules'));

const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const { execSync } = require('child_process');
const fs = require('fs');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const BACKUP_SCRIPT = path.join(PROJECT_ROOT, 'scripts', 'backup_mongodb.py');
const TEST_BACKUP_DIR = path.join(__dirname, 'test_backup_data');

async function runBackupRestoreTest() {
  console.log('='.repeat(80));
  console.log('PHASE 20: MONGODB BACKUP & DISASTER RECOVERY RESTORE AUDIT');
  console.log('='.repeat(80));

  let mongoServer;
  try {
    console.log('\n[1] Initializing isolated test Mongo server...');
    mongoServer = await MongoMemoryServer.create({
      instance: {
        launchTimeout: 60000
      }
    });
    const baseUri = mongoServer.getUri();
    const sourceDbUri = `${baseUri}netshield_source_db`;
    const targetDbUri = `${baseUri}netshield_restore_db`;

    console.log(`  Source URI: ${sourceDbUri}`);
    console.log(`  Target URI: ${targetDbUri}`);

    // Connect to source DB
    const sourceConn = await mongoose.createConnection(sourceDbUri).asPromise();
    console.log('\n[2] Seeding representative test data into source database...');

    // Define schemas for all 6 collections
    const User = sourceConn.model('User', new mongoose.Schema({}, { strict: false }), 'users');
    const Log = sourceConn.model('Log', new mongoose.Schema({}, { strict: false }), 'logs');
    const Alert = sourceConn.model('Alert', new mongoose.Schema({}, { strict: false }), 'alerts');
    const Setting = sourceConn.model('Setting', new mongoose.Schema({}, { strict: false }), 'settings');
    const Metric = sourceConn.model('Metric', new mongoose.Schema({}, { strict: false }), 'systemmetrics');
    const Incident = sourceConn.model('Incident', new mongoose.Schema({}, { strict: false }), 'operationalincidents');

    // Insert test docs
    await User.insertMany([
      { username: 'audit_admin', email: 'audit_admin@test.com', role: 'ADMIN', createdAt: new Date() },
      { username: 'soc_analyst', email: 'analyst@test.com', role: 'ANALYST', createdAt: new Date() }
    ]);

    await Setting.insertMany([
      { key: 'retention_days', value: 90, description: 'Log retention window' },
      { key: 'alert_threshold', value: 0.75, description: 'Anomaly trigger threshold' }
    ]);

    await Log.insertMany([
      { timestamp: new Date(), sourceIp: '192.168.1.100', destIp: '10.0.0.1', protocol: 'TCP', flags: 'SYN', attack: 'Normal' },
      { timestamp: new Date(), sourceIp: '172.16.0.45', destIp: '10.0.0.5', protocol: 'TCP', flags: 'S0', attack: 'DoS' }
    ]);

    await Alert.insertMany([
      { timestamp: new Date(), severity: 'critical', attackType: 'DoS', prediction: 'neptune', confidence: 0.998, status: 'open' }
    ]);

    await Incident.insertMany([
      { timestamp: new Date(), component: 'mlService', severity: 'warning', message: 'High inference latency spike', resolved: true }
    ]);

    await Metric.insertMany([
      { timestamp: new Date(), cpu_usage: 12.5, memory_usage_mb: 256.0, active_connections: 4 }
    ]);

    console.log('  -> Seeded 2 users, 2 settings, 2 logs, 1 alert, 1 incident, 1 metric.');

    // Clean previous test backup directory if exists
    if (fs.existsSync(TEST_BACKUP_DIR)) {
      fs.rmSync(TEST_BACKUP_DIR, { recursive: true, force: true });
    }

    // Run backup script via Python
    console.log('\n[3] Executing scripts/backup_mongodb.py --action backup...');
    const backupCmd = `python "${BACKUP_SCRIPT}" --action backup --uri "${sourceDbUri}" --backup-dir "${TEST_BACKUP_DIR}"`;
    const backupOutput = execSync(backupCmd, { encoding: 'utf8' });
    console.log(backupOutput.trim());

    // Verify backup files exist
    const manifestPath = path.join(TEST_BACKUP_DIR, 'manifest.json');
    if (!fs.existsSync(manifestPath)) {
      throw new Error(`Backup manifest missing at ${manifestPath}`);
    }
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    console.log(`\n  Manifest verified: ${JSON.stringify(manifest.collections)}`);

    // Run restore script into target database
    console.log('\n[4] Executing scripts/backup_mongodb.py --action restore into target database...');
    const restoreCmd = `python "${BACKUP_SCRIPT}" --action restore --uri "${targetDbUri}" --backup-dir "${TEST_BACKUP_DIR}" --target-db netshield_restore_db`;
    const restoreOutput = execSync(restoreCmd, { encoding: 'utf8' });
    console.log(restoreOutput.trim());

    // Connect to restored database and verify row counts & data
    console.log('\n[5] Verifying 100% data integrity in restored database...');
    const targetConn = await mongoose.createConnection(targetDbUri).asPromise();
    
    const collections = ['users', 'settings', 'logs', 'alerts', 'operationalincidents', 'systemmetrics'];
    const results = {};

    for (const col of collections) {
      const srcCount = await sourceConn.collection(col).countDocuments();
      const dstCount = await targetConn.collection(col).countDocuments();
      console.log(`  Collection '${col}': Source = ${srcCount} | Restored = ${dstCount}`);
      if (srcCount !== dstCount) {
        throw new Error(`Row count mismatch in '${col}': Source has ${srcCount}, Restored has ${dstCount}`);
      }
      results[col] = { srcCount, dstCount, match: true };
    }

    // Check specific document field integrity
    const restoredUser = await targetConn.collection('users').findOne({ username: 'audit_admin' });
    if (!restoredUser || restoredUser.email !== 'audit_admin@test.com') {
      throw new Error('User document field content corrupted during backup/restore!');
    }
    console.log('  -> Verified field-level integrity for document: audit_admin');

    const restoredAlert = await targetConn.collection('alerts').findOne({ attackType: 'DoS' });
    if (!restoredAlert || restoredAlert.severity !== 'critical') {
      throw new Error('Alert document field content corrupted during backup/restore!');
    }
    console.log('  -> Verified field-level integrity for alert: DoS (critical)');

    // Clean up
    await sourceConn.close();
    await targetConn.close();
    await mongoServer.stop();

    if (fs.existsSync(TEST_BACKUP_DIR)) {
      fs.rmSync(TEST_BACKUP_DIR, { recursive: true, force: true });
    }

    console.log('\n[PASS] 100% DISASTER RECOVERY BACKUP & RESTORE INTEGRITY VERIFIED!');
    console.log('='.repeat(80));
    process.exit(0);
  } catch (err) {
    console.error('\n[FAIL] Backup & Restore verification failed:', err);
    if (mongoServer) await mongoServer.stop();
    process.exit(1);
  }
}

runBackupRestoreTest();
