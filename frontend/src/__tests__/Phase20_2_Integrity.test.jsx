import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { describe, test, expect, vi, beforeEach } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import SeverityBadge from '../components/common/SeverityBadge';
import ThreatsPage from '../pages/ThreatsPage';
import DashboardPage from '../pages/DashboardPage';
import * as socService from '../services/socService';
import * as AuthContext from '../auth/AuthContext';

// Polyfill ResizeObserver for recharts ResponsiveContainer in Vitest jsdom
global.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};

vi.mock('../auth/AuthContext', () => ({
  useAuth: vi.fn()
}));

vi.mock('../services/socService');

vi.mock('../services/socket', () => ({
  subscribeToEvent: vi.fn(() => () => {})
}));

describe('PHASE 20.2: Predictions Feed Classification & Threat Visibility Integrity', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    AuthContext.useAuth.mockReturnValue({ role: 'ADMIN', user: { username: 'analyst1' } });
    
    socService.getModelInfo.mockResolvedValue({
      data: {
        models: {
          nsl_kdd: { model_version: 'v1.3' },
          cicids2017: { model_version: 'v1.2' }
        }
      }
    });
    socService.getAlerts.mockResolvedValue({ data: [], pagination: { total: 0 } });
    socService.getMetrics.mockResolvedValue({
      data: {
        measured: {
          totalFlows: 664,
          benignFlows: 635,
          maliciousFlows: 29,
          activeAlerts: 29,
          avgLatencyMs: 3.8,
          detectionRate: 4.37
        },
        timeWindow: 'All Time'
      }
    });
    socService.getPredictions.mockResolvedValue({
      data: [],
      pagination: { page: 1, limit: 20, total: 0, totalPages: 1 }
    });
  });

  describe('Part A & B: SeverityBadge Classification Mapping', () => {
    test('A. CICIDS benign record displays BENIGN / Benign badge', () => {
      const { container } = render(<SeverityBadge prediction="BENIGN" isBenign={true} />);
      expect(screen.getByText('BENIGN')).toBeInTheDocument();
      const badge = container.querySelector('.badge');
      expect(badge).toHaveClass('badge-benign');
    });

    test('B. CICIDS attack record displays actual ML attack class (e.g., DDoS, PortScan, DoS Hulk)', () => {
      const { rerender } = render(<SeverityBadge prediction="DDoS" isBenign={false} severity="high" />);
      expect(screen.getByText('DDoS')).toBeInTheDocument();

      rerender(<SeverityBadge prediction="PortScan" isBenign={false} severity="medium" />);
      expect(screen.getByText('PortScan')).toBeInTheDocument();

      rerender(<SeverityBadge prediction="DoS Hulk" isBenign={false} severity="high" />);
      expect(screen.getByText('DoS Hulk')).toBeInTheDocument();
    });

    test('C. NSL-KDD Normal record displays Normal badge', () => {
      const { container } = render(<SeverityBadge prediction="Normal" isBenign={true} />);
      expect(screen.getByText('Normal')).toBeInTheDocument();
      const badge = container.querySelector('.badge');
      expect(badge).toHaveClass('badge-benign');
    });

    test('D. NSL-KDD attack record displays actual predicted class (DoS, Probe, U2R, R2L)', () => {
      const { rerender } = render(<SeverityBadge prediction="DoS" isBenign={false} severity="high" />);
      expect(screen.getByText('DoS')).toBeInTheDocument();

      rerender(<SeverityBadge prediction="Probe" isBenign={false} severity="medium" />);
      expect(screen.getByText('Probe')).toBeInTheDocument();

      rerender(<SeverityBadge prediction="U2R" isBenign={false} severity="critical" />);
      expect(screen.getByText('U2R')).toBeInTheDocument();

      rerender(<SeverityBadge prediction="R2L" isBenign={false} severity="high" />);
      expect(screen.getByText('R2L')).toBeInTheDocument();
    });
  });

  describe('Part E & F: ThreatsPage Dataset Isolation & Prediction vs Ground Truth', () => {
    test('E & F. Feed renders ML prediction, handles ground truth distinction, and filters by dataset', async () => {
      socService.getPredictions.mockImplementation((params) => {
        if (params?.datasetType === 'cicids2017') {
          return Promise.resolve({
            data: [
              {
                _id: 'cicids_log_1',
                timestamp: '2026-09-05T10:00:00.000Z',
                datasetType: 'cicids2017',
                prediction: 'DDoS',
                confidence: 0.9991,
                processingLatencyMs: 8.5,
                sourceInfo: { groundTruth: 'DDoS Attack Sample' }
              },
              {
                _id: 'cicids_log_2',
                timestamp: '2026-09-05T09:50:00.000Z',
                datasetType: 'cicids2017',
                prediction: 'BENIGN',
                confidence: 0.9966,
                processingLatencyMs: 9.1,
                sourceInfo: { groundTruth: 'BENIGN' }
              }
            ],
            pagination: { total: 2, page: 1, totalPages: 1 }
          });
        }
        return Promise.resolve({
          data: [
            {
              _id: 'nsl_log_1',
              timestamp: '2026-09-05T10:05:00.000Z',
              datasetType: 'nsl_kdd',
              prediction: 'Probe',
              confidence: 0.9999,
              processingLatencyMs: 5.2,
              sourceInfo: { groundTruth: 'Probe (satan)' }
            }
          ],
          pagination: { total: 1, page: 1, totalPages: 1 }
        });
      });

      render(
        <MemoryRouter>
          <ThreatsPage />
        </MemoryRouter>
      );

      // Initially loads with default datasetType (all)
      await waitFor(() => {
        expect(screen.getAllByText('Probe').length).toBeGreaterThan(0);
        expect(screen.getByText('Probe (satan)')).toBeInTheDocument();
      });

      // Switch dataset to cicids2017
      const select = screen.getByDisplayValue(/All Datasets/i);
      fireEvent.change(select, { target: { value: 'cicids2017' } });

      // Verify that DDoS and BENIGN predictions are displayed and GT distinction is visible
      await waitFor(() => {
        expect(screen.getAllByText('DDoS').length).toBeGreaterThan(0);
        expect(screen.getByText('DDoS Attack Sample')).toBeInTheDocument();
        expect(screen.getAllByText('BENIGN').length).toBeGreaterThan(0);
      });
    });
  });

  describe('Part G & H: Traffic Ratio Consistency & Tooltip Styling', () => {
    test('G. Traffic ratio preserves benign + threat = total flows in metrics', async () => {
      const mockMetrics = {
        totalFlows: 664,
        benignFlows: 635,
        maliciousFlows: 29,
        activeAlerts: 29,
        avgLatencyMs: 3.8,
        detectionRate: 4.37
      };

      expect(mockMetrics.benignFlows + mockMetrics.maliciousFlows).toBe(mockMetrics.totalFlows);

      socService.getMetrics.mockResolvedValue({
        data: {
          measured: mockMetrics,
          timeWindow: 'All Time'
        }
      });
      socService.getPredictions.mockResolvedValue({ data: [], pagination: { total: 0, page: 1, totalPages: 1 } });

      render(
        <MemoryRouter>
          <DashboardPage />
        </MemoryRouter>
      );

      await waitFor(() => {
        expect(screen.getByText('664')).toBeInTheDocument();
        expect(screen.getByText('635')).toBeInTheDocument();
        expect(screen.getAllByText('29').length).toBeGreaterThan(0);
      });
    });
  });
});
