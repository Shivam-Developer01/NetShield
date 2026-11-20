import { io } from 'socket.io-client';

const getSocketUrl = () => {
  const envUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000/api';
  return envUrl.replace(/\/api\/?$/, '');
};

let socket = null;
const statusListeners = new Set();
let currentStatus = 'disconnected';

const updateStatus = (status) => {
  currentStatus = status;
  statusListeners.forEach((listener) => {
    try {
      listener(status);
    } catch (e) {
      console.error('Error in socket status listener:', e);
    }
  });
};

export const initSocket = () => {
  if (socket) return socket;

  const url = getSocketUrl();
  socket = io(url, {
    withCredentials: true,
    autoConnect: false,
    transports: ['websocket', 'polling'],
    reconnection: true,
    reconnectionAttempts: 10,
    reconnectionDelay: 2000
  });

  socket.on('connect', () => {
    updateStatus('connected');
  });

  socket.on('disconnect', (reason) => {
    updateStatus('disconnected');
  });

  socket.on('connect_error', (error) => {
    updateStatus('disconnected');
  });

  socket.io.on('reconnect_attempt', () => {
    updateStatus('reconnecting');
  });

  return socket;
};

export const connectSocket = () => {
  const s = initSocket();
  if (!s.connected && currentStatus !== 'connecting') {
    updateStatus('connecting');
    s.connect();
  }
  return s;
};

export const disconnectSocket = () => {
  if (socket) {
    socket.disconnect();
    socket = null;
  }
  updateStatus('disconnected');
};

export const getSocket = () => socket;

export const getSocketStatus = () => currentStatus;

export const subscribeToEvent = (eventName, callback) => {
  const s = initSocket();
  s.on(eventName, callback);
  return () => {
    s.off(eventName, callback);
  };
};

export const addStatusListener = (callback) => {
  statusListeners.add(callback);
  callback(currentStatus);
  return () => {
    statusListeners.delete(callback);
  };
};
