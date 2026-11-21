/**
 * NetShield Backend HTTP Server Entry Point
 * Connects to MongoDB database and starts Express HTTP server listener.
 */

const app = require('./app');
const config = require('./config/env');
const { connectDatabase, disconnectDatabase } = require('./config/database');
const { initSocketServer, closeSocketServer } = require('./realtime/socketServer');
const logger = require('./utils/logger');

let server;

const startServer = async () => {
  try {
    // 1. Connect to MongoDB
    await connectDatabase();

    // 2. Start HTTP Server
    server = app.listen(config.port, () => {
      logger.info(`NetShield Node.js Backend listening on port ${config.port} [${config.nodeEnv}]`);
      logger.info(`ML Service URL target: ${config.mlServiceUrl}`);
    });

    // 3. Initialize Socket.IO Server
    initSocketServer(server);
  } catch (error) {
    logger.error('Failed to start NetShield Backend Server:', { error: error.message });
    process.exit(1);
  }
};

const handleShutdown = async (signal) => {
  logger.warn(`Received ${signal}. Shutting down NetShield Backend Server gracefully...`);
  await closeSocketServer();
  if (server) {
    server.close(async () => {
      logger.info('HTTP server closed.');
      await disconnectDatabase();
      process.exit(0);
    });
  } else {
    await disconnectDatabase();
    process.exit(0);
  }
};

process.on('SIGINT', () => handleShutdown('SIGINT'));
process.on('SIGTERM', () => handleShutdown('SIGTERM'));

if (require.main === module) {
  startServer();
}

module.exports = {
  startServer
};
