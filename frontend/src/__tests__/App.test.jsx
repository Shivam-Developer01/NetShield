import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { describe, test, expect, vi, beforeEach } from 'vitest';
import App from '../App';
import * as socService from '../services/socService';
import * as authService from '../services/authService';

vi.mock('../services/socService');
vi.mock('../services/authService');

// Mock ResizeObserver for Recharts compatibility in JSDOM
global.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};

describe('React SOC Dashboard Component Suite', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    authService.getMe.mockResolvedValue({
      success: true,
      user: { id: 'admin1', username: 'SysAdmin', email: 'admin@test.com', role: 'ADMIN', isActive: true }
    });
    socService.getHealth.mockResolvedValue({
      status: 'healthy',
      database: { status: 'connected' },
      ml_service: { status: 'healthy' }
    });
    socService.getMetrics.mockResolvedValue({
      data: {
        measured: { totalFlows: 150, benignFlows: 140, maliciousFlows: 10, activeAlerts: 2, processingLatencyMs: 15.4 },
        calculated: { detectionRate: 6.67 }
      }
    });
    socService.getPredictions.mockResolvedValue({
      data: [
        { _id: 'log1', timestamp: new Date().toISOString(), datasetType: 'nsl_kdd', prediction: 'Normal', confidence: 0.99, modelVersion: 'v1', processingLatencyMs: 12 }
      ],
      pagination: { page: 1, limit: 5, total: 1, totalPages: 1 }
    });
    socService.getAlerts.mockResolvedValue({
      data: [
        { _id: 'alert1', timestamp: new Date().toISOString(), severity: 'high', attackType: 'DoS', prediction: 'DoS', confidence: 0.98, datasetType: 'nsl_kdd', status: 'open', description: 'DoS attack' }
      ],
      pagination: { page: 1, limit: 5, total: 1, totalPages: 1 }
    });
    socService.getModelInfo.mockResolvedValue({
      data: {
        models: {
          nsl_kdd: { model_version: 'NetShield-NSLKDD-XGBoost-v1.1-remediated', feature_count: 37, algorithm: 'XGBoost (Hist)', accuracy: 0.7764, weighted_f1: 0.7408, provenance: 'Benchmark' },
          cicids2017: { model_version: 'NetShield-CICIDS2017-XGBoost-v1.1-remediated', feature_count: 43, algorithm: 'XGBoost (Hist)', accuracy: 0.9885, weighted_f1: 0.9879, provenance: 'Sub-Capture' }
        }
      }
    });
  });

  test('1. Application renders successfully with header and brand title', async () => {
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText('NET')).toBeInTheDocument();
      expect(screen.getByText('SHIELD')).toBeInTheDocument();
      expect(screen.getByText(/Cybersecurity Operations Center/i)).toBeInTheDocument();
    });
  });

  test('2. Dashboard loads backend metrics and renders total flow statistics', async () => {
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText(/150/)).toBeInTheDocument();
      expect(screen.getByText(/6.67%/)).toBeInTheDocument();
    });
  });

  test('3. Verify no secrets or credentials exposed in environment / API setup', () => {
    const apiBaseUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000/api';
    expect(apiBaseUrl).not.toContain('password');
    expect(apiBaseUrl).not.toContain('secret');
    expect(apiBaseUrl).not.toContain('mongodb://');
  });

  test('4. Dashboard displays healthy backend status badge', async () => {
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText(/Backend: Healthy/i)).toBeInTheDocument();
    });
  });

  test('5. Error state renders user-friendly error banner when backend fails', async () => {
    socService.getMetrics.mockRejectedValueOnce(new Error('Backend connection failed'));
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText(/Backend connection failed/i)).toBeInTheDocument();
    });
  });

  test('6. getMetrics is called with datasetType scoped parameter', async () => {
    render(<App />);
    await waitFor(() => {
      expect(socService.getMetrics).toHaveBeenCalledWith(
        expect.objectContaining({ datasetType: expect.any(String) })
      );
    });
  });
});
