import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, test, expect, vi, beforeEach } from 'vitest';
import PredictPage from '../pages/PredictPage';
import * as AuthContext from '../auth/AuthContext';
import * as socService from '../services/socService';

vi.mock('../auth/AuthContext', () => ({
  useAuth: vi.fn()
}));

vi.mock('../services/socService', () => ({
  submitPrediction: vi.fn()
}));

describe('PHASE 20.5: Manual CICIDS2017 DoS Hulk Prediction Integrity Audit Tests', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    AuthContext.useAuth.mockReturnValue({
      user: { username: 'soc_analyst' },
      role: 'ANALYST'
    });
  });

  test('switching dataset to CICIDS2017 renders DoS Hulk, DDoS, and Benign preset buttons', () => {
    render(<PredictPage />);

    const select = screen.getByRole('combobox');
    fireEvent.change(select, { target: { value: 'cicids2017' } });

    expect(screen.getByRole('button', { name: /load benign sample/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /load ddos attack sample/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /load dos hulk attack sample/i })).toBeInTheDocument();
  });

  test('clicking "Load DoS Hulk Attack Sample" loads authentic schema including variance features', () => {
    render(<PredictPage />);

    // Switch to CICIDS2017
    const select = screen.getByRole('combobox');
    fireEvent.change(select, { target: { value: 'cicids2017' } });

    // Click Hulk preset
    const hulkBtn = screen.getByRole('button', { name: /load dos hulk attack sample/i });
    fireEvent.click(hulkBtn);

    const textarea = screen.getByRole('textbox');
    const parsed = JSON.parse(textarea.value);

    // Verify key features from Wednesday-workingHours.pcap_ISCX.csv (Row 74860)
    expect(parsed['Destination Port']).toBe(80);
    expect(parsed['Flow Duration']).toBe(1878);
    expect(parsed['Fwd Packet Length Std']).toBeCloseTo(220.547803);
    expect(parsed['Bwd Packet Length Std']).toBeCloseTo(2182.468304);
    expect(parsed['Total Fwd Packets']).toBe(3);
    expect(parsed['Total Backward Packets']).toBe(6);
    expect(parsed['Packet Length Variance']).toBeCloseTo(3558249.789);
  });

  test('submitting DoS Hulk prediction sends correct datasetType and sourceInfo groundTruth', async () => {
    socService.submitPrediction.mockResolvedValue({
      predictions: [{
        prediction: 'DoS Hulk',
        confidence: 0.9969,
        class_probabilities: {
          'BENIGN': 0.0001,
          'DoS Hulk': 0.9969,
          'DDoS': 0.003
        }
      }],
      alert_generated: true,
      alert_id: 'alt-hulk-123',
      severity: 'CRITICAL',
      model_version: 'NetShield-CICIDS2017-TwoStage-v1.2'
    });

    render(<PredictPage />);

    // Switch to CICIDS2017
    const select = screen.getByRole('combobox');
    fireEvent.change(select, { target: { value: 'cicids2017' } });

    // Click Hulk preset
    fireEvent.click(screen.getByRole('button', { name: /load dos hulk attack sample/i }));

    // Submit
    const submitBtn = screen.getByRole('button', { name: /submit prediction request/i });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(socService.submitPrediction).toHaveBeenCalledTimes(1);
    });

    const callArg = socService.submitPrediction.mock.calls[0][0];
    expect(callArg.datasetType).toBe('cicids2017');
    expect(callArg.sourceInfo.groundTruth).toBe('DoS Hulk');
    expect(callArg.inputData['Destination Port']).toBe(80);

    // Verify rendered output
    expect(await screen.findByText(/prediction matched/i)).toBeInTheDocument();
    expect(screen.getAllByText('DoS Hulk').length).toBeGreaterThan(0);
    expect(screen.getAllByText('99.69%').length).toBeGreaterThan(0);
  });

  test('transparently renders "Missed Attack (False Negative)" alert when model misclassifies attack as BENIGN', async () => {
    // Simulate the exact scenario observed in the screenshot audit
    socService.submitPrediction.mockResolvedValue({
      predictions: [{
        prediction: 'BENIGN',
        confidence: 0.7794,
        class_probabilities: {
          'BENIGN': 0.7794,
          'DoS Hulk': 0.2206
        }
      }],
      alert_generated: false,
      log_id: 'log-benign-456',
      severity: 'INFO',
      model_version: 'NetShield-CICIDS2017-TwoStage-v1.2'
    });

    render(<PredictPage />);

    // Switch to CICIDS2017
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'cicids2017' } });

    // Load Hulk preset (Ground Truth: DoS Hulk)
    fireEvent.click(screen.getByRole('button', { name: /load dos hulk attack sample/i }));

    // Submit
    fireEvent.click(screen.getByRole('button', { name: /submit prediction request/i }));

    // Verify the UI clearly exposes the failure instead of treating it as a success
    expect(await screen.findByText(/missed attack \(false negative\)/i)).toBeInTheDocument();
    expect(screen.getByText(/model classified ground-truth threat/i)).toBeInTheDocument();
    expect(screen.getAllByText('BENIGN').length).toBeGreaterThan(0);
    expect(screen.getAllByText('77.94%').length).toBeGreaterThan(0);
  });

  test('VIEWER role is prevented from submitting predictions and shown read-only message', () => {
    AuthContext.useAuth.mockReturnValue({
      user: { username: 'auditor' },
      role: 'VIEWER'
    });

    render(<PredictPage />);

    expect(screen.queryByRole('button', { name: /submit prediction request/i })).not.toBeInTheDocument();
    expect(screen.getByText(/read-only role \(viewer\)/i)).toBeInTheDocument();
  });
});
