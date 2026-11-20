import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { describe, test, expect, vi, beforeEach } from 'vitest';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import AlertInvestigationPage from '../pages/AlertInvestigationPage';
import * as analyticsService from '../services/analyticsService';

vi.mock('../services/analyticsService', () => ({
  getInvestigation: vi.fn(),
  getRelatedActivity: vi.fn()
}));

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useParams: () => ({ id: 'alert123' })
  };
});

describe('Phase 15: React AlertInvestigationPage Component Suite', () => {
  beforeEach(() => {
    vi.resetAllMocks();

    analyticsService.getInvestigation.mockResolvedValue({
      data: {
        alert: {
          id: 'alert123',
          timestamp: '2026-08-26T10:00:00.000Z',
          severity: 'high',
          attackType: 'neptune',
          prediction: 'neptune',
          confidence: 0.98,
          datasetType: 'nsl_kdd',
          modelVersion: 'NetShield-NSLKDD-XGBoost-v1.0',
          status: 'open',
          description: 'Neptune DoS attack detected'
        },
        relatedLog: {
          id: 'log123',
          timestamp: '2026-08-26T10:00:00.000Z',
          processingLatencyMs: 14.5
        },
        timeline: [
          { stage: 'PREDICTION_RECEIVED', label: 'Network Flow Data Received', timestamp: '2026-08-26T10:00:00.000Z' },
          { stage: 'ML_INFERENCE', label: 'FastAPI XGBoost Inference Completed', timestamp: '2026-08-26T10:00:00.000Z' },
          { stage: 'ALERT_CREATED', label: 'Security Alert Triggered (HIGH)', timestamp: '2026-08-26T10:00:00.000Z' }
        ]
      }
    });

    analyticsService.getRelatedActivity.mockResolvedValue({
      data: {
        timeWindowMinutes: 15,
        logs: [
          { id: 'log1', timestamp: '2026-08-26T09:55:00.000Z', prediction: 'Normal', confidence: 0.99, datasetType: 'nsl_kdd', processingLatencyMs: 12.0 }
        ],
        alerts: []
      }
    });
  });

  test('1. AlertInvestigationPage renders investigation details and timeline stages', async () => {
    render(
      <MemoryRouter initialEntries={['/alerts/alert123/investigate']}>
        <Routes>
          <Route path="/alerts/:id/investigate" element={<AlertInvestigationPage />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/Threat Attack: neptune/i)).toBeInTheDocument();
      expect(screen.getByText('Network Flow Data Received')).toBeInTheDocument();
      expect(screen.getByText('FastAPI XGBoost Inference Completed')).toBeInTheDocument();
      expect(screen.getByText('98.0%')).toBeInTheDocument();
    });
  });

  test('2. Surrounding network activity table renders nearby flow logs', async () => {
    render(
      <MemoryRouter initialEntries={['/alerts/alert123/investigate']}>
        <Routes>
          <Route path="/alerts/:id/investigate" element={<AlertInvestigationPage />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Surrounding Network Activity (±15 Minutes Bounded Window)')).toBeInTheDocument();
      expect(screen.getByText('Normal')).toBeInTheDocument();
      expect(screen.getByText('12 ms')).toBeInTheDocument();
    });
  });

  test('3. Clicking Back to Alerts button navigates to /alerts', async () => {
    render(
      <MemoryRouter initialEntries={['/alerts/alert123/investigate']}>
        <Routes>
          <Route path="/alerts/:id/investigate" element={<AlertInvestigationPage />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      const backBtn = screen.getByText('Back to Alerts');
      fireEvent.click(backBtn);
      expect(mockNavigate).toHaveBeenCalledWith('/alerts');
    });
  });
});
