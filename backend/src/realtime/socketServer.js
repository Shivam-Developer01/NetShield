const { Server } = require('socket.io');
const config = require('../config/env');
const socketAuth = require('./socketAuth');
const { setIO, publishSystemHealth } = require('./eventPublisher');
const { ROOMS, ROLES } = require('./eventTypes');
const { logAuditEvent } = require('../utils/auditLogger');
const logger = require('../utils/logger');
const { checkHealth: getMlHealth } = require('../services/mlService');
const mongoose = require('mongoose');

let io = null;
let healthInterval = null;

/**
 * Assigns socket connection to authorized room hierarchy based on user role
 */
const assignRooms = (socket) => {
  const role = socket.user?.role;

  // All authenticated users belong to soc:viewers
  socket.join(ROOMS.VIEWERS);

  if (role === ROLES.ANALYST || role === ROLES.ADMIN) {
    socket.join(ROOMS.ANALYSTS);
  }

  if (role === ROLES.ADMIN) {
    socket.join(ROOMS.ADMINS);
  }

  logger.debug(`[SocketServer] Socket ${socket.id} (user:${socket.user.email}, role:${role}) joined rooms: ${Array.from(socket.rooms).join(', ')}`);
};

/**
 * Periodically broadcasts aggregated system health telemetry
 */
const broadcastPeriodicHealth = async () => {
  try {
    const dbConnected = mongoose.connection.readyState === 1;
    let mlHealthStatus = 'unavailable';

    try {
      const mlHealth = await getMlHealth();
      mlHealthStatus = mlHealth.status || 'degraded';
    } catch {
      mlHealthStatus = 'unavailable';
    }

    const overallStatus = (dbConnected && mlHealthStatus === 'healthy') ? 'healthy' : 'degraded';

    publishSystemHealth({
      backend: 'healthy',
      database: dbConnected ? 'connected' : 'disconnected',
      mlService: mlHealthStatus,
      status: overallStatus,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    logger.error(`[SocketServer] Error in periodic health broadcast: ${err.message}`);
  }
};

/**
 * Initializes Socket.IO real-time server instance
 */
const initSocketServer = (httpServer) => {
  const allowedOrigins = config.corsOrigins.includes(',')
    ? config.corsOrigins.split(',').map((o) => o.trim())
    : [config.corsOrigins];

  io = new Server(httpServer, {
    cors: {
      origin: allowedOrigins,
      credentials: true,
    },
    transports: ['websocket', 'polling'],
    pingTimeout: 30000,
    pingInterval: 10000,
  });

  // Apply authentication middleware
  io.use(socketAuth);

  // Bind IO instance to publisher module
  setIO(io);

  io.on('connection', (socket) => {
    try {
      // Server-side RBAC room assignment
      assignRooms(socket);

      logAuditEvent('SOCKET_CONNECTED', {
        success: true,
        userId: socket.user.id,
        email: socket.user.email,
        role: socket.user.role,
        details: { socketId: socket.id }
      });

      // Disallow client-side arbitrary room join attempts
      socket.on('join_room', (room) => {
        logAuditEvent('SOCKET_UNAUTHORIZED_EVENT', {
          success: false,
          userId: socket.user.id,
          email: socket.user.email,
          role: socket.user.role,
          details: { action: 'join_room_attempt', requestedRoom: room }
        });
        socket.emit('error', { message: 'Forbidden: Server controls room membership' });
      });

      socket.on('disconnect', (reason) => {
        logAuditEvent('SOCKET_DISCONNECTED', {
          success: true,
          userId: socket.user?.id,
          email: socket.user?.email,
          role: socket.user?.role,
          details: { socketId: socket.id, reason }
        });
      });

      socket.on('error', (err) => {
        logger.warn(`[SocketServer] Client socket error on ${socket.id}: ${err.message}`);
      });

    } catch (err) {
      logger.error(`[SocketServer] Error handling connection for socket ${socket.id}: ${err.message}`);
    }
  });

  // Start periodic 20-second system health broadcast
  if (!healthInterval) {
    healthInterval = setInterval(broadcastPeriodicHealth, 20000);
  }

  logger.info(`[SocketServer] Socket.IO server initialized successfully [CORS: ${allowedOrigins.join(', ')}]`);
  return io;
};

/**
 * Safely stops Socket.IO server and clears health intervals
 */
const closeSocketServer = async () => {
  if (healthInterval) {
    clearInterval(healthInterval);
    healthInterval = null;
  }
  if (io) {
    await new Promise((resolve) => io.close(resolve));
    io = null;
    setIO(null);
    logger.info('[SocketServer] Socket.IO server closed successfully.');
  }
};

module.exports = {
  initSocketServer,
  closeSocketServer,
  getIO: () => io,
};
