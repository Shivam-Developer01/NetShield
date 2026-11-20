import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, test, expect, vi, beforeEach } from 'vitest';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import Header from '../components/layout/Header';
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

describe('PHASE 20.3: Analytics N/A Fix, Navbar Dataset Filter & Refresh UX', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    AuthContext.useAuth.mockReturnValue({
      user: { username: 'sec_admin' },
      role: 'ADMIN',
      socketStatus: 'connected',
      logout: vi.fn()
    });

    analyticsService.getOverview.mockResolvedValue({
      totalPredictions: 200,
      benignPredictions: 180,
      maliciousPredictions: 20,
      activeAlerts: 4,
      criticalAlerts: 1,
      detectionRate: 10.0,
      averageConfidence: 0.95,
      averageProcessingLatencyMs: 25.0,
      topAttackType: 'neptune',
      recentThreatCount: 5
    });

    analyticsService.getTrends.mockResolvedValue({
      interval: 'day',
      data: [{ timestamp: '2026-09-01', total: 200, benign: 180, malicious: 20, alerts: 4 }]
    });

    analyticsService.getAttacks.mockResolvedValue({
      data: [{ attackType: 'neptune', count: 20, percentage: 100, averageConfidence: 0.95, severity: 'high' }]
    });

    analyticsService.getSeverity.mockResolvedValue({
      data: {
        benign: { count: 180, percentage: 90.0 },
        critical: { count: 1, percentage: 0.5 },
        high: { count: 3, percentage: 1.5 },
        medium: { count: 0, percentage: 0 },
        low: { count: 0, percentage: 0 }
      }
    });

    analyticsService.getModels.mockResolvedValue({
      data: [
        { datasetType: 'nsl_kdd', modelVersion: 'NetShield-NSLKDD-XGBoost-v1.0', predictionCount: 150, maliciousCount: 15, detectionRate: 10, averageConfidence: 0.96, averageLatency: 22.1 },
        { datasetType: 'cicids2017', modelVersion: 'NetShield-CICIDS2017-TwoStage-v1.2', predictionCount: 50, maliciousCount: 5, detectionRate: 10, averageConfidence: 0.93, averageLatency: 28.4 }
      ]
    });
  });

  describe('Part A: Analytics N/A Handling & Explanation', () => {
    test('1. Renders descriptive explanation when averageTimeToAckMs and averageTimeToResolutionMs are null', async () => {
      analyticsService.getAlertAnalytics.mockResolvedValue({
        data: {
          totalAlerts: 10,
          openAlerts: 10,
          acknowledgedAlerts: 0,
          resolvedAlerts: 0,
          averageTimeToAckMs: null,
          averageTimeToResolutionMs: null
        }
      });

      render(
        <MemoryRouter>
          <AnalyticsPage globalDatasetFilter="all" />
        </MemoryRouter>
      );

      await waitFor(() => {
        expect(screen.getByText('N/A — No acknowledged alerts')).toBeInTheDocument();
        expect(screen.getByText('N/A — No resolved alerts')).toBeInTheDocument();
      });
    });

    test('2. Renders formatted seconds when acknowledged and resolved timestamps exist', async () => {
      analyticsService.getAlertAnalytics.mockResolvedValue({
        data: {
          totalAlerts: 10,
          openAlerts: 7,
          acknowledgedAlerts: 2,
          resolvedAlerts: 1,
          averageTimeToAckMs: 14500,
          averageTimeToResolutionMs: 62300
        }
      });

      render(
        <MemoryRouter>
          <AnalyticsPage globalDatasetFilter="all" />
        </MemoryRouter>
      );

      await waitFor(() => {
        expect(screen.getByText('14.5s')).toBeInTheDocument();
        expect(screen.getByText('62.3s')).toBeInTheDocument();
      });
    });
  });

  describe('Part B: Navbar Route-Aware Dataset Filter Visibility', () => {
    const renderHeaderAtRoute = (initialRoute) => {
      return render(
        <MemoryRouter initialEntries={[initialRoute]}>
          <Routes>
            <Route
              path="*"
              element={
                <Header
                  healthStatus={{ status: 'healthy', database: { status: 'connected' }, ml_service: { status: 'healthy' } }}
                  datasetFilter="all"
                  setDatasetFilter={vi.fn()}
                  onRefresh={vi.fn()}
                  lastUpdated="2026-09-05T00:00:00.000Z"
                />
              }
            />
          </Routes>
        </MemoryRouter>
      );
    };

    test('1. Dataset filter is VISIBLE on root dashboard route "/"', () => {
      renderHeaderAtRoute('/');
      expect(screen.getByLabelText('Dataset Filter')).toBeInTheDocument();
    });

    test('2. Dataset filter is VISIBLE on "/dashboard" route', () => {
      renderHeaderAtRoute('/dashboard');
      expect(screen.getByLabelText('Dataset Filter')).toBeInTheDocument();
    });

    test('3. Dataset filter is HIDDEN on "/analytics" route', () => {
      renderHeaderAtRoute('/analytics');
      expect(screen.queryByLabelText('Dataset Filter')).toBeNull();
    });

    test('4. Dataset filter is HIDDEN on "/operations" route', () => {
      renderHeaderAtRoute('/operations');
      expect(screen.queryByLabelText('Dataset Filter')).toBeNull();
    });

    test('5. Dataset filter is HIDDEN on "/threats" route', () => {
      renderHeaderAtRoute('/threats');
      expect(screen.queryByLabelText('Dataset Filter')).toBeNull();
    });

    test('6. Dataset filter is HIDDEN on "/alerts" route', () => {
      renderHeaderAtRoute('/alerts');
      expect(screen.queryByLabelText('Dataset Filter')).toBeNull();
    });

    test('7. Dataset filter is HIDDEN on "/predict" route', () => {
      renderHeaderAtRoute('/predict');
      expect(screen.queryByLabelText('Dataset Filter')).toBeNull();
    });
  });

  describe('Part C: Navbar Refresh Button Behavior & Layout', () => {
    test('1. Refresh button triggers onRefresh handler when clicked', () => {
      const mockRefresh = vi.fn();
      render(
        <MemoryRouter initialEntries={['/analytics']}>
          <Routes>
            <Route
              path="*"
              element={
                <Header
                  healthStatus={{ status: 'healthy' }}
                  datasetFilter="all"
                  setDatasetFilter={vi.fn()}
                  onRefresh={mockRefresh}
                  lastUpdated="2026-09-05T00:00:00.000Z"
                />
              }
            />
          </Routes>
        </MemoryRouter>
      );

      const refreshBtn = screen.getByRole('button', { name: /refresh telemetry/i });
      expect(refreshBtn).toBeInTheDocument();
      fireEvent.click(refreshBtn);
      expect(mockRefresh).toHaveBeenCalledTimes(1);
    });

    test('2. User credentials and logout remain visible and aligned even when dataset filter is hidden', () => {
      render(
        <MemoryRouter initialEntries={['/operations']}>
          <Routes>
            <Route
              path="*"
              element={
                <Header
                  healthStatus={{ status: 'healthy' }}
                  datasetFilter="all"
                  setDatasetFilter={vi.fn()}
                  onRefresh={vi.fn()}
                  lastUpdated="2026-09-05T00:00:00.000Z"
                />
              }
            />
          </Routes>
        </MemoryRouter>
      );

      expect(screen.getByText('sec_admin')).toBeInTheDocument();
      expect(screen.getByText('ADMIN')).toBeInTheDocument();
      expect(screen.getByTitle('Logout session')).toBeInTheDocument();
    });
  });
});
