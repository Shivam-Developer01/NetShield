import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, test, expect, vi, beforeEach } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import AlertsPage from '../pages/AlertsPage';
import api, { getCsrfCookie, setCsrfToken, getStoredCsrfToken } from '../services/api';
import * as AuthContext from '../auth/AuthContext';
import * as socService from '../services/socService';

vi.mock('../auth/AuthContext', () => ({
  useAuth: vi.fn(() => ({
    user: { username: 'sec_admin' },
    role: 'ADMIN',
    socketStatus: 'connected',
    logout: vi.fn()
  }))
}));

vi.mock('../services/socService', () => ({
  getAlerts: vi.fn(),
  updateAlertStatus: vi.fn()
}));

describe('PHASE 20.4: Security Alert Acknowledge/Resolve CSRF Integrity', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    AuthContext.useAuth.mockReturnValue({
      user: { username: 'sec_admin' },
      role: 'ADMIN',
      socketStatus: 'connected',
      logout: vi.fn()
    });
    sessionStorage.clear();
    // Clear cookies in jsdom
    document.cookie.split(';').forEach(c => {
      document.cookie = c.replace(/^ +/, '').replace(/=.*/, '=;expires=' + new Date().toUTCString() + ';path=/');
    });

    socService.getAlerts.mockResolvedValue({
      data: [
        {
          _id: 'alert-12345',
          timestamp: '2026-09-05T10:00:00.000Z',
          severity: 'high',
          attackType: 'DoS',
          prediction: 'DoS',
          confidence: 0.98,
          datasetType: 'nsl_kdd',
          status: 'open',
          description: 'High volume DoS attack detected'
        },
        {
          _id: 'alert-67890',
          timestamp: '2026-09-05T10:05:00.000Z',
          severity: 'medium',
          attackType: 'Probe',
          prediction: 'Probe',
          confidence: 0.85,
          datasetType: 'cicids2017',
          status: 'acknowledged',
          description: 'Port scanning probe detected'
        }
      ],
      pagination: {
        total: 2,
        page: 1,
        limit: 20,
        totalPages: 1
      }
    });
  });

  test('1. CSRF utility methods correctly retrieve token from cookie and fallback store', () => {
    document.cookie = 'XSRF-TOKEN=test-cookie-token-12345; path=/';
    expect(getCsrfCookie()).toBe('test-cookie-token-12345');
    expect(getStoredCsrfToken()).toBe('test-cookie-token-12345');

    // Test fallback when cookie absent
    document.cookie = 'XSRF-TOKEN=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
    setCsrfToken('test-session-token-67890');
    expect(getStoredCsrfToken()).toBe('test-session-token-67890');
  });

  test('2. Centralized request interceptor attaches X-XSRF-TOKEN header to state-changing requests', async () => {
    setCsrfToken('mock-csrf-token-abc');

    const config = {
      method: 'patch',
      url: '/alerts/alert-12345',
      headers: {
        set: vi.fn(),
        get: vi.fn()
      }
    };

    // Run the request interceptor handler registered in api.js
    const interceptorHandler = api.interceptors.request.handlers[0].fulfilled;
    const modifiedConfig = interceptorHandler(config);

    expect(config.headers.set).toHaveBeenCalledWith('X-XSRF-TOKEN', 'mock-csrf-token-abc');
  });

  test('3. Clicking Acknowledge calls updateAlertStatus with "acknowledged" and refetches alerts', async () => {
    socService.updateAlertStatus.mockResolvedValue({
      success: true,
      data: { _id: 'alert-12345', status: 'acknowledged' }
    });

    render(
      <MemoryRouter>
        <AlertsPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('High volume DoS attack detected')).toBeInTheDocument();
    });

    const ackButtons = screen.getAllByRole('button', { name: /^Ack$/i });
    expect(ackButtons.length).toBeGreaterThanOrEqual(1);

    fireEvent.click(ackButtons[0]);

    await waitFor(() => {
      expect(socService.updateAlertStatus).toHaveBeenCalledWith('alert-12345', 'acknowledged');
      expect(socService.getAlerts).toHaveBeenCalledTimes(2); // Initial fetch + post-update fetch
    });
  });

  test('4. Clicking Resolve calls updateAlertStatus with "resolved" and refetches alerts', async () => {
    socService.updateAlertStatus.mockResolvedValue({
      success: true,
      data: { _id: 'alert-67890', status: 'resolved' }
    });

    render(
      <MemoryRouter>
        <AlertsPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Port scanning probe detected')).toBeInTheDocument();
    });

    const resolveButtons = screen.getAllByRole('button', { name: /^Resolve$/i });
    expect(resolveButtons.length).toBeGreaterThanOrEqual(2);

    // resolveButtons[1] corresponds to alert-67890 (the second row)
    fireEvent.click(resolveButtons[1]);

    await waitFor(() => {
      expect(socService.updateAlertStatus).toHaveBeenCalledWith('alert-67890', 'resolved');
      expect(socService.getAlerts).toHaveBeenCalledTimes(2);
    });
  });

  test('5. Alert update error prompts user with error dialog without throwing unhandled exceptions', async () => {
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {});
    socService.updateAlertStatus.mockRejectedValue(new Error('Invalid or missing CSRF token. State-changing request rejected.'));

    render(
      <MemoryRouter>
        <AlertsPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('High volume DoS attack detected')).toBeInTheDocument();
    });

    const ackButtons = screen.getAllByRole('button', { name: /^Ack$/i });
    fireEvent.click(ackButtons[0]);

    await waitFor(() => {
      expect(alertSpy).toHaveBeenCalledWith(
        'Failed to update alert status: Invalid or missing CSRF token. State-changing request rejected.'
      );
    });

    alertSpy.mockRestore();
  });
});
