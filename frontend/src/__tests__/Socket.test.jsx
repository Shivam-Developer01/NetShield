import React from 'react';
import { render, screen } from '@testing-library/react';
import { describe, test, expect, vi, beforeEach } from 'vitest';
import ConnectionStatusBadge from '../components/common/ConnectionStatusBadge';
import RealtimeNotification from '../components/common/RealtimeNotification';
import * as AuthContext from '../auth/AuthContext';

vi.mock('../auth/AuthContext', () => ({
  useAuth: vi.fn()
}));

vi.mock('../services/socket', () => ({
  subscribeToEvent: vi.fn(() => () => {})
}));

describe('Phase 14: React Socket.IO Real-Time Component Suite', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  test('1. ConnectionStatusBadge renders WS LIVE pill when socket is connected', () => {
    AuthContext.useAuth.mockReturnValue({ socketStatus: 'connected' });
    render(<ConnectionStatusBadge />);
    expect(screen.getByText('WS LIVE')).toBeInTheDocument();
  });

  test('2. ConnectionStatusBadge renders REST FALLBACK pill when socket is disconnected', () => {
    AuthContext.useAuth.mockReturnValue({ socketStatus: 'disconnected' });
    render(<ConnectionStatusBadge />);
    expect(screen.getByText('REST FALLBACK')).toBeInTheDocument();
  });

  test('3. ConnectionStatusBadge renders RECONNECTING pill when reconnecting', () => {
    AuthContext.useAuth.mockReturnValue({ socketStatus: 'reconnecting' });
    render(<ConnectionStatusBadge />);
    expect(screen.getByText('RECONNECTING')).toBeInTheDocument();
  });

  test('4. RealtimeNotification mounts cleanly and handles empty notifications', () => {
    const { container } = render(<RealtimeNotification />);
    expect(container.firstChild).toBeNull();
  });
});
