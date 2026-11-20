import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import OperationsPage from '../pages/OperationsPage';
import { subscribeToEvent } from '../services/socket';
import * as socService from '../services/socService';

// Mock socket service
vi.mock('../services/socket', () => ({
  subscribeToEvent: vi.fn(() => vi.fn()),
  initSocket: vi.fn(),
  getSocketStatus: vi.fn(() => 'connected'),
  addStatusListener: vi.fn(() => vi.fn())
}));

// Mock socService
vi.mock('../services/socService', () => ({
  getOperationalHealth: vi.fn(),
  getOperationalMetrics: vi.fn(),
  getOperationalIncidents: vi.fn(),
  updateOperationalIncidentStatus: vi.fn()
}));

describe('OperationsPage Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    socService.getOperationalHealth.mockResolvedValue({
      status: 'healthy',
      services: {
        backend: { status: 'healthy', uptimeSeconds: 120 },
        mongodb: { status: 'healthy', state: 'connected' },
        mlService: { status: 'healthy' },
        sensor: { status: 'healthy', lastSeenAt: '2026-09-06T00:00:00.000Z' },
        socket: { status: 'healthy', activeConnections: 2 }
      }
    });

    socService.getOperationalMetrics.mockResolvedValue({
      http: { totalRequests: 100, errorRatePercent: 0.0, latency: { avg: 45, p95: 120 } },
      ml: { totalRequests: 50, failureCount: 0, latency: { avg: 30 } },
      sensor: { packetsProcessed: 500, flowsCreated: 100, activeFlows: 5 }
    });

    socService.getOperationalIncidents.mockResolvedValue([
      {
        _id: 'inc-1',
        type: 'HIGH_LATENCY',
        severity: 'HIGH',
        source: 'mlService',
        message: 'ML latency spike detected',
        status: 'OPEN',
        occurrenceCount: 3,
        createdAt: '2026-09-06T00:00:00.000Z'
      },
      {
        _id: 'inc-2',
        type: 'SENSOR_OFFLINE',
        severity: 'CRITICAL',
        source: 'sensor',
        message: 'Sensor packet drop spike',
        status: 'ACKNOWLEDGED',
        occurrenceCount: 1,
        createdAt: '2026-09-06T00:05:00.000Z'
      }
    ]);

    socService.updateOperationalIncidentStatus.mockImplementation((id, status) => {
      return Promise.resolve({
        _id: id,
        type: 'HIGH_LATENCY',
        severity: 'HIGH',
        source: 'mlService',
        message: 'ML latency spike detected',
        status: status,
        occurrenceCount: 3,
        createdAt: '2026-09-06T00:00:00.000Z'
      });
    });
  });

  it('1. Renders title, subtitle, and styled Refresh Status button', async () => {
    render(<OperationsPage userRole="ADMIN" />);
    expect(await screen.findByText(/Operations & Health Monitoring/i)).toBeInTheDocument();
    expect(screen.getByText(/Real-time infrastructure health, operational metrics, and incident management/i)).toBeInTheDocument();

    const refreshBtn = screen.getByRole('button', { name: /refresh status/i });
    expect(refreshBtn).toBeInTheDocument();
    expect(refreshBtn).toHaveClass('btn');
  });

  it('2. Renders all 5 subsystem health cards with status badges and metrics', async () => {
    render(<OperationsPage userRole="ADMIN" />);
    
    // Subsystem names
    expect(await screen.findByText(/^Backend$/i)).toBeInTheDocument();
    expect(screen.getByText(/^MongoDB$/i)).toBeInTheDocument();
    expect(screen.getByText(/^ML Service$/i)).toBeInTheDocument();
    expect(screen.getAllByText(/^Sensor$/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/^WebSocket$/i)).toBeInTheDocument();

    // Subtitles
    expect(screen.getByText(/Node.js Express Server/i)).toBeInTheDocument();
    expect(screen.getByText(/Database Store/i)).toBeInTheDocument();
    expect(screen.getByText(/FastAPI Inference/i)).toBeInTheDocument();
    expect(screen.getByText(/Scapy Capture/i)).toBeInTheDocument();
    expect(screen.getByText(/Socket.IO Streamer/i)).toBeInTheDocument();

    // Values & Metrics
    expect(screen.getByText(/Uptime: 120s/i)).toBeInTheDocument();
    expect(screen.getByText(/State: connected/i)).toBeInTheDocument();
    expect(screen.getByText(/Engine: XGBoost v1.0/i)).toBeInTheDocument();
    expect(screen.getByText(/Connections: 2/i)).toBeInTheDocument();
  });

  it('3. Renders performance metrics cards correctly', async () => {
    render(<OperationsPage userRole="ADMIN" />);

    expect(await screen.findByText(/HTTP Requests Total/i)).toBeInTheDocument();
    expect(screen.getByText('100')).toBeInTheDocument();
    expect(screen.getByText(/Error Rate: 0%/i)).toBeInTheDocument();

    expect(screen.getByText(/API Latency \(avg \/ p95\)/i)).toBeInTheDocument();
    expect(screen.getByText(/45 ms \/ 120 ms/i)).toBeInTheDocument();

    expect(screen.getByText(/ML Inference Total \/ Failures/i)).toBeInTheDocument();
    expect(screen.getByText(/50 \/ 0/i)).toBeInTheDocument();
    expect(screen.getByText(/Avg Latency: 30 ms/i)).toBeInTheDocument();

    expect(screen.getByText(/Sensor Packets \/ Flows/i)).toBeInTheDocument();
    expect(screen.getByText(/500 \/ 100/i)).toBeInTheDocument();
    expect(screen.getByText(/Active Flows: 5/i)).toBeInTheDocument();
  });

  it('4. Handles missing or null service states gracefully as UNKNOWN / Unavailable', async () => {
    socService.getOperationalHealth.mockResolvedValue({ status: 'unknown', services: {} });
    socService.getOperationalMetrics.mockResolvedValue(null);
    socService.getOperationalIncidents.mockResolvedValue([]);

    render(<OperationsPage userRole="ADMIN" />);

    const unknownBadges = await screen.findAllByText('UNKNOWN');
    expect(unknownBadges.length).toBe(5);

    const unavailableTexts = screen.getAllByText(/Unavailable/i);
    expect(unavailableTexts.length).toBeGreaterThanOrEqual(5);
  });

  it('5. Renders operational incident log table with custom styled controls', async () => {
    render(<OperationsPage userRole="ADMIN" />);

    expect(await screen.findByText(/Operational Incidents Log/i)).toBeInTheDocument();
    expect(screen.getByText(/ML latency spike detected/i)).toBeInTheDocument();
    expect(screen.getByText(/Sensor packet drop spike/i)).toBeInTheDocument();

    // Form selects are styled with .form-select
    const severitySelect = screen.getByLabelText(/filter incidents by severity/i);
    const statusSelect = screen.getByLabelText(/filter incidents by status/i);
    expect(severitySelect).toHaveClass('form-select');
    expect(statusSelect).toHaveClass('form-select');

    // Table is contained in .table-container and uses .soc-table
    const table = screen.getByRole('table');
    expect(table).toHaveClass('soc-table');
  });

  it('6. Filters incidents by severity and status correctly', async () => {
    render(<OperationsPage userRole="ADMIN" />);

    expect(await screen.findByText(/ML latency spike detected/i)).toBeInTheDocument();
    expect(screen.getByText(/Sensor packet drop spike/i)).toBeInTheDocument();

    // Filter by CRITICAL severity
    const severitySelect = screen.getByLabelText(/filter incidents by severity/i);
    fireEvent.change(severitySelect, { target: { value: 'CRITICAL' } });

    expect(screen.queryByText(/ML latency spike detected/i)).not.toBeInTheDocument();
    expect(screen.getByText(/Sensor packet drop spike/i)).toBeInTheDocument();

    // Filter by OPEN status
    const statusSelect = screen.getByLabelText(/filter incidents by status/i);
    fireEvent.change(statusSelect, { target: { value: 'OPEN' } });

    expect(screen.getByText(/No operational incidents found matching filters./i)).toBeInTheDocument();
  });

  it('7. Allows ADMIN/ANALYST to acknowledge and resolve incidents', async () => {
    render(<OperationsPage userRole="ADMIN" />);

    const ackBtn = await screen.findByRole('button', { name: /ack/i });
    expect(ackBtn).toBeInTheDocument();
    expect(ackBtn).toHaveClass('btn');

    fireEvent.click(ackBtn);

    await waitFor(() => {
      expect(socService.updateOperationalIncidentStatus).toHaveBeenCalledWith('inc-1', 'ACKNOWLEDGED');
    });
  });

  it('8. Hides action buttons for VIEWER role', async () => {
    render(<OperationsPage userRole="VIEWER" />);

    expect(await screen.findByText(/ML latency spike detected/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /ack/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /resolve/i })).not.toBeInTheDocument();
    expect(screen.getAllByText(/No action/i).length).toBe(2);
  });

  it('9. Subscribes to Socket.IO operational events on mount', async () => {
    render(<OperationsPage userRole="ADMIN" />);
    expect(await screen.findByText(/Operations & Health Monitoring/i)).toBeInTheDocument();

    expect(subscribeToEvent).toHaveBeenCalledWith('system.health.changed', expect.any(Function));
    expect(subscribeToEvent).toHaveBeenCalledWith('system.incident.created', expect.any(Function));
    expect(subscribeToEvent).toHaveBeenCalledWith('system.incident.updated', expect.any(Function));
  });

  it('10. Refresh button triggers data re-fetching', async () => {
    render(<OperationsPage userRole="ADMIN" />);

    expect(await screen.findByText(/Operations & Health Monitoring/i)).toBeInTheDocument();
    const initialCallCount = socService.getOperationalHealth.mock.calls.length;

    const refreshBtn = screen.getByRole('button', { name: /refresh status/i });
    fireEvent.click(refreshBtn);

    await waitFor(() => {
      expect(socService.getOperationalHealth.mock.calls.length).toBeGreaterThan(initialCallCount);
    });
  });
});
