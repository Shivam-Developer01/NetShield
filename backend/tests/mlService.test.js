const axios = require('axios');
const mlService = require('../src/services/mlService');
const metricsCollector = require('../src/utils/metricsCollector');

jest.mock('axios');

describe('ML Service IPC Client & Operational Metrics', () => {
  beforeEach(() => {
    metricsCollector.reset();
    jest.clearAllMocks();
  });

  test('predict() successfully returns prediction payload from FastAPI and records metrics', async () => {
    const mockFastAPIResponse = {
      data: {
        dataset_type: 'nsl_kdd',
        model_version: 'NetShield-NSLKDD-XGBoost-v1.0',
        records_processed: 1,
        predictions: [
          {
            record_index: 0,
            prediction: 'Normal',
            prediction_index: 1,
            confidence: 0.9999,
            class_probabilities: { Normal: 0.9999, DoS: 0.0001 }
          }
        ]
      }
    };
    axios.post.mockResolvedValueOnce(mockFastAPIResponse);

    const initialTotal = metricsCollector.mlStats.inferenceRequestsTotal;
    const initialSuccess = metricsCollector.mlStats.inferenceSuccess;
    const initialFailures = metricsCollector.mlStats.inferenceFailures;

    const result = await mlService.predict('nsl_kdd', { duration: 0, protocol_type: 'tcp' }, 'req-123');
    expect(result.dataset_type).toEqual('nsl_kdd');
    expect(result.predictions.length).toEqual(1);
    expect(result.predictions[0].prediction).toEqual('Normal');
    expect(result).toHaveProperty('client_latency_ms');

    // Verify ML operational metrics incremented correctly
    expect(metricsCollector.mlStats.inferenceRequestsTotal).toBe(initialTotal + 1);
    expect(metricsCollector.mlStats.inferenceSuccess).toBe(initialSuccess + 1);
    expect(metricsCollector.mlStats.inferenceFailures).toBe(initialFailures);
    expect(metricsCollector.mlStats.datasetUsage.nsl_kdd).toBe(1);
    expect(metricsCollector.mlStats.inferenceLatenciesMs.length).toBe(1);

    const summary = metricsCollector.getMetricsSummary();
    expect(summary.ml.totalRequests).toBe(1);
    expect(summary.ml.successCount).toBe(1);
    expect(summary.ml.failureCount).toBe(0);
    expect(summary.ml.latency.avg).toBeGreaterThanOrEqual(0);
  });

  test('predict() throws 504 MLServiceError on request timeout and records failure metric', async () => {
    const timeoutError = new Error('timeout of 5000ms exceeded');
    timeoutError.code = 'ECONNABORTED';
    axios.post.mockRejectedValueOnce(timeoutError);

    const initialTotal = metricsCollector.mlStats.inferenceRequestsTotal;
    const initialFailures = metricsCollector.mlStats.inferenceFailures;
    const initialSuccess = metricsCollector.mlStats.inferenceSuccess;

    await expect(mlService.predict('nsl_kdd', { duration: 0 }))
      .rejects.toThrow('timed out');

    // Verify failed inference metrics
    expect(metricsCollector.mlStats.inferenceRequestsTotal).toBe(initialTotal + 1);
    expect(metricsCollector.mlStats.inferenceFailures).toBe(initialFailures + 1);
    expect(metricsCollector.mlStats.inferenceSuccess).toBe(initialSuccess);

    const summary = metricsCollector.getMetricsSummary();
    expect(summary.ml.totalRequests).toBe(1);
    expect(summary.ml.failureCount).toBe(1);
    expect(summary.ml.successCount).toBe(0);
  });

  test('predict() throws 503 MLServiceError on connection refusal and records failure metric', async () => {
    const connError = new Error('connect ECONNREFUSED 127.0.0.1:8000');
    connError.code = 'ECONNREFUSED';
    axios.post.mockRejectedValueOnce(connError);

    await expect(mlService.predict('cicids2017', { duration: 0 }))
      .rejects.toThrow('unavailable');

    expect(metricsCollector.mlStats.inferenceRequestsTotal).toBe(1);
    expect(metricsCollector.mlStats.inferenceFailures).toBe(1);
    expect(metricsCollector.mlStats.datasetUsage.cicids2017).toBe(1);
  });

  test('invalid payload response triggers exactly one failure record without double counting', async () => {
    // Malformed response (no predictions array)
    axios.post.mockResolvedValueOnce({
      data: { dataset_type: 'nsl_kdd', predictions: [] }
    });

    await expect(mlService.predict('nsl_kdd', { duration: 0 }))
      .rejects.toThrow('Invalid prediction payload');

    expect(metricsCollector.mlStats.inferenceRequestsTotal).toBe(1);
    expect(metricsCollector.mlStats.inferenceFailures).toBe(1);
    expect(metricsCollector.mlStats.inferenceSuccess).toBe(0);
  });
});
