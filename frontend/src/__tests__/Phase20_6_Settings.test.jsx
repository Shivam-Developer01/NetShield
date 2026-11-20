import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, test, expect, vi, beforeEach } from 'vitest';
import SettingsPage from '../pages/SettingsPage';
import * as AuthContext from '../auth/AuthContext';
import * as socService from '../services/socService';

vi.mock('../auth/AuthContext', () => ({
  useAuth: vi.fn()
}));

vi.mock('../services/socService', () => ({
  getSettings: vi.fn(),
  updateSetting: vi.fn()
}));

const MOCK_SETTINGS = [
  {
    key: 'alertThresholdConfidence',
    value: 80,
    description: 'Minimum model confidence required to trigger high severity alert.'
  },
  {
    key: 'enableAutoResolution',
    value: false,
    description: 'Automatically resolve alerts when benign traffic resumes.'
  },
  {
    key: 'maxLogRetentionDays',
    value: 30,
    description: 'Number of days to retain threat prediction logs in MongoDB.'
  },
  {
    key: 'systemNotificationEmail',
    value: 'admin@netshield.local',
    description: 'Contact email for security threat digests.'
  }
];

describe('PHASE 20.6: Settings Functionality & Behavioral Integrity UI Suite', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    AuthContext.useAuth.mockReturnValue({
      user: { username: 'sec_admin' },
      role: 'ADMIN'
    });
    socService.getSettings.mockResolvedValue({
      success: true,
      data: MOCK_SETTINGS
    });
  });

  test('renders all 4 configurable parameters with metadata labels and hot-reload notice', async () => {
    render(<SettingsPage />);

    expect(await screen.findByText('System & Dashboard Settings')).toBeInTheDocument();
    expect(screen.getByText(/Hot-Reload: Changes take effect dynamically without server restarts/i)).toBeInTheDocument();

    expect(screen.getByText('Alert Threshold Confidence')).toBeInTheDocument();
    expect(screen.getByText('% (0 - 100)')).toBeInTheDocument();

    expect(screen.getByText('Enable Auto-Resolution')).toBeInTheDocument();
    expect(screen.getByText('Toggle (Boolean)')).toBeInTheDocument();

    expect(screen.getByText('Max Log Retention Period')).toBeInTheDocument();
    expect(screen.getByText('Days (1 - 3650)')).toBeInTheDocument();

    expect(screen.getByText('System Notification Email')).toBeInTheDocument();
    expect(screen.getByText('Email Address')).toBeInTheDocument();
  });

  test('saving a setting calls updateSetting and displays dynamic success message', async () => {
    socService.updateSetting.mockResolvedValue({
      success: true,
      data: { key: 'alertThresholdConfidence', value: 85 }
    });

    render(<SettingsPage />);

    expect(await screen.findByText('Alert Threshold Confidence')).toBeInTheDocument();

    const saveButtons = screen.getAllByRole('button', { name: /save/i });
    // First button corresponds to alertThresholdConfidence
    fireEvent.click(saveButtons[0]);

    await waitFor(() => {
      expect(socService.updateSetting).toHaveBeenCalledWith(
        'alertThresholdConfidence',
        80,
        'Minimum model confidence required to trigger high severity alert.'
      );
    });

    expect(await screen.findByText(/Setting 'alertThresholdConfidence' saved successfully/i)).toBeInTheDocument();
  });

  test('displays inline error banner when backend returns a validation failure without browser alert', async () => {
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {});
    socService.updateSetting.mockRejectedValue({
      response: {
        data: {
          error: {
            message: 'systemNotificationEmail must be a valid email address.'
          }
        }
      }
    });

    render(<SettingsPage />);

    expect(await screen.findByText('System Notification Email')).toBeInTheDocument();

    const saveButtons = screen.getAllByRole('button', { name: /save/i });
    // Fourth button corresponds to systemNotificationEmail
    fireEvent.click(saveButtons[3]);

    expect(await screen.findByText('systemNotificationEmail must be a valid email address.')).toBeInTheDocument();
    expect(alertSpy).not.toHaveBeenCalled();
    alertSpy.mockRestore();
  });

  test('VIEWER role is shown read-only notice and all input controls are disabled', async () => {
    AuthContext.useAuth.mockReturnValue({
      user: { username: 'auditor' },
      role: 'VIEWER'
    });

    render(<SettingsPage />);

    expect(await screen.findByText(/Read-Only Mode: Settings modification requires an account with the ADMIN role/i)).toBeInTheDocument();

    const saveButtons = screen.getAllByRole('button', { name: /save/i });
    saveButtons.forEach(btn => {
      expect(btn).toBeDisabled();
    });
  });
});
