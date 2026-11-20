import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { describe, test, expect, vi, beforeEach } from 'vitest';
import AnalyticsPage from '../pages/AnalyticsPage';
import * as AuthContext from '../auth/AuthContext';
import * as analyticsService from '../services/analyticsService';

// Polyfill ResizeObserver for recharts ResponsiveContainer in Vitest jsdom
global.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};

vi.mock('../auth/AuthContext', () => ({
  useAuth: vi.fn()
}));

vi.mock('../services/analyticsService', () => ({
  getOverview: vi.fn(),
  getTrends: vi.fn(),
  getAttacks: vi.fn(),
  getSeverity: vi.fn(),
  getModels: vi.fn(),
  getAlertAnalytics: vi.fn(),
  downloadExport: vi.fn()
}));

vi.mock('../services/socket', () => ({
  subscribeToEvent: vi.fn(() => () => {})
}));

describe('Phase 15: React AnalyticsPage Component Suite', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    AuthContext.useAuth.mockReturnValue({ role: 'ADMIN' });

    analyticsService.getOverview.mockResolvedValue({
      totalPredictions: 150,
      benignPredictions: 100,
      maliciousPredictions: 50,
      activeAlerts: 5,
      criticalAlerts: 2,
      detectionRate: 33.33,
      averageConfidence: 0.94,
      averageProcessingLatencyMs: 14.2,
      topAttackType: 'neptune',
      recentThreatCount: 12
    });

    analyticsService.getTrends.mockResolvedValue({
      interval: 'day',
      data: [{ timestamp: '2026-08-26', total: 150, benign: 100, malicious: 50, alerts: 5 }]
    });

    analyticsService.getAttacks.mockResolvedValue({
      data: [{ attackType: 'neptune', count: 30, percentage: 60, averageConfidence: 0.95, severity: 'high' }]
    });

    analyticsService.getSeverity.mockResolvedValue({
      data: {
        benign: { count: 100, percentage: 66.7 },
        critical: { count: 2, percentage: 1.3 },
        high: { count: 3, percentage: 2.0 },
        medium: { count: 0, percentage: 0 },
        low: { count: 0, percentage: 0 }
      }
    });

    analyticsService.getModels.mockResolvedValue({
      data: [
        { datasetType: 'nsl_kdd', predictionCount: 100, maliciousCount: 30, detectionRate: 30, averageConfidence: 0.95, averageLatency: 12.5 },
        { datasetType: 'cicids2017', predictionCount: 50, maliciousCount: 20, detectionRate: 40, averageConfidence: 0.93, averageLatency: 16.1 }
      ]
    });

    analyticsService.getAlertAnalytics.mockResolvedValue({
      data: {
        totalAlerts: 5,
        openAlerts: 2,
        acknowledgedAlerts: 2,
        resolvedAlerts: 1,
        averageTimeToAckMs: 12000,
        averageTimeToResolutionMs: 45000
      }
    });
  });

  test('1. AnalyticsPage renders header title and KPI statistics cards', async () => {
    render(<AnalyticsPage />);

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Advanced Security Analytics/i })).toBeInTheDocument();
      expect(screen.getByText(/Total Predictions/i)).toBeInTheDocument();
      expect(screen.getByText(/Malicious Traffic/i)).toBeInTheDocument();
    });
  });

  test('2. Export CSV button is rendered for ADMIN and triggers download', async () => {
    render(<AnalyticsPage />);

    await waitFor(() => {
      const exportBtn = screen.getByText('Export CSV');
      expect(exportBtn).toBeInTheDocument();
      fireEvent.click(exportBtn);
      expect(analyticsService.downloadExport).toHaveBeenCalled();
    });
  });

  test('3. Export CSV button is hidden for VIEWER role', async () => {
    AuthContext.useAuth.mockReturnValue({ role: 'VIEWER' });
    render(<AnalyticsPage />);

    await waitFor(() => {
      expect(screen.queryByText('Export CSV')).toBeNull();
    });
  });
});
