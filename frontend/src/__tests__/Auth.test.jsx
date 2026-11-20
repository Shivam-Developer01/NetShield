import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { describe, test, expect, vi, beforeEach } from 'vitest';
import App from '../App';
import * as authService from '../services/authService';
import * as socService from '../services/socService';

vi.mock('../services/authService');
vi.mock('../services/socService');

global.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};

describe('Phase 11: React Authentication Component & RBAC Suite', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    window.history.pushState({}, '', '/'); // Reset browser location back to root '/'
    socService.getHealth.mockResolvedValue({ status: 'healthy' });
    socService.getMetrics.mockResolvedValue({ data: { measured: { totalFlows: 10, benignFlows: 10, maliciousFlows: 0, activeAlerts: 0, processingLatencyMs: 5 }, calculated: { detectionRate: 0 } } });
    socService.getPredictions.mockResolvedValue({ data: [], pagination: { page: 1, limit: 5, total: 0, totalPages: 1 } });
    socService.getAlerts.mockResolvedValue({ data: [], pagination: { page: 1, limit: 5, total: 0, totalPages: 1 } });
  });

  test('1. Unauthenticated user accessing protected route is redirected to Login page', async () => {
    authService.getMe.mockRejectedValue(new Error('Unauthenticated'));
    render(<App />);

    await waitFor(() => {
      expect(screen.getByText(/Sign In to SOC Dashboard/i)).toBeInTheDocument();
    });
  });

  test('2. Login page submits credentials and handles authentication errors', async () => {
    authService.getMe.mockRejectedValue(new Error('Unauthenticated'));
    authService.loginUser.mockRejectedValue(new Error('Invalid email or password.'));

    render(<App />);

    await waitFor(() => {
      expect(screen.getByPlaceholderText(/admin@netshield.local/i)).toBeInTheDocument();
    });

    fireEvent.change(screen.getByPlaceholderText(/admin@netshield.local/i), { target: { value: 'wrong@test.com' } });
    fireEvent.change(screen.getByPlaceholderText(/••••••••••••/i), { target: { value: 'WrongPassword' } });
    fireEvent.click(screen.getByRole('button', { name: /Sign In to SOC Dashboard/i }));

    await waitFor(() => {
      expect(screen.getByText(/Invalid email or password/i)).toBeInTheDocument();
    });
  });

  test('3. Authenticated ADMIN session renders dashboard with full navigation including User Management', async () => {
    authService.getMe.mockResolvedValue({
      success: true,
      user: { id: 'admin1', username: 'SysAdmin', email: 'admin@test.com', role: 'ADMIN', isActive: true }
    });

    render(<App />);

    await waitFor(() => {
      expect(screen.getByText('SysAdmin')).toBeInTheDocument();
      expect(screen.getByText(/User Management/i)).toBeInTheDocument();
    });
  });

  test('4. Authenticated VIEWER session hides User Management nav item', async () => {
    authService.getMe.mockResolvedValue({
      success: true,
      user: { id: 'viewer1', username: 'ReadOnlyViewer', email: 'viewer@test.com', role: 'VIEWER', isActive: true }
    });

    render(<App />);

    await waitFor(() => {
      expect(screen.getByText('ReadOnlyViewer')).toBeInTheDocument();
      expect(screen.queryByText(/User Management/i)).not.toBeInTheDocument();
    });
  });
});
