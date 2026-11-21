/**
 * ML Microservice Client Service
 * Encapsulates HTTP inter-process communication (IPC) with the independent FastAPI ML Service.
 * Note: Node.js MUST NOT load .joblib models, import Python code, or perform feature preprocessing/inference.
 */

const axios = require('axios');
const config = require('../config/env');
const metricsCollector = require('../utils/metricsCollector');

class MLServiceError extends Error {
  constructor(message, statusCode, details = null) {
    super(message);
    this.name = 'MLServiceError';
    this.statusCode = statusCode;
    this.details = details;
  }
}

/**
 * Dispatches an inference prediction request to the FastAPI ML service.
 * @param {string} datasetType - 'nsl_kdd' | 'cicids2017'
 * @param {Object} inputData - Raw network feature record dictionary
 * @param {string} [requestId] - Optional X-Request-ID correlation header
 * @returns {Promise<Object>} FastAPI prediction response payload
 */
const predict = async (datasetType, inputData, requestId = null) => {
  const targetUrl = `${config.mlServiceUrl}/predict`;
  const payload = {
    dataset_type: datasetType,
    input_data: inputData
  };

  const headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  };
  if (requestId) {
    headers['X-Request-ID'] = requestId;
  }

  const startTime = Date.now();
  try {
    const response = await axios.post(targetUrl, payload, {
      timeout: config.mlServiceTimeoutMs,
      headers
    });

    const durationMs = Date.now() - startTime;
    const data = response.data;

    // Validate expected structure from FastAPI /predict
    if (!data || !data.dataset_type || !Array.isArray(data.predictions) || data.predictions.length === 0) {
      metricsCollector.recordMlInference(false, datasetType, durationMs);
      throw new MLServiceError(
        'Invalid prediction payload structure received from ML Service.',
        502
      );
    }

    // Append Node.js IPC measured latency
    data.client_latency_ms = durationMs;

    // Record successful ML inference in operational metrics
    metricsCollector.recordMlInference(true, datasetType, durationMs);

    return data;
  } catch (error) {
    const durationMs = Date.now() - startTime;
    // Record failed ML inference in operational metrics if not already recorded above
    if (!(error instanceof MLServiceError && error.statusCode === 502 && error.message.includes('Invalid prediction payload'))) {
      metricsCollector.recordMlInference(false, datasetType, durationMs);
    }
    if (error instanceof MLServiceError) {
      throw error;
    }

    if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
      throw new MLServiceError(
        `FastAPI ML Service request timed out after ${config.mlServiceTimeoutMs}ms.`,
        504
      );
    }

    if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
      throw new MLServiceError(
        'FastAPI ML Service is unavailable. Connection refused.',
        503
      );
    }

    if (error.response) {
      const status = error.response.status;
      const detail = error.response.data?.detail || error.response.data?.message || 'ML Service error';
      throw new MLServiceError(
        `ML Service returned error ${status}: ${detail}`,
        status >= 500 ? 502 : status,
        detail
      );
    }

    throw new MLServiceError(
      `Failed to communicate with ML Service: ${error.message}`,
      503
    );
  }
};

/**
 * Checks the health status of the FastAPI ML Service.
 * @param {string} [requestId] - Optional X-Request-ID correlation header
 * @returns {Promise<Object>} FastAPI health status payload
 */
const checkHealth = async (requestId = null) => {
  const targetUrl = `${config.mlServiceUrl}/health`;
  const headers = {};
  if (requestId) headers['X-Request-ID'] = requestId;

  try {
    const response = await axios.get(targetUrl, {
      timeout: 3000,
      headers
    });
    return response.data;
  } catch (error) {
    return {
      status: 'unavailable',
      error: error.message
    };
  }
};

/**
 * Retrieves loaded model metadata and verification provenance from the FastAPI ML Service.
 * Falls back to local artifact metadata if the ML service HTTP endpoint is temporarily unreachable.
 */
const getModelInfo = async (requestId = null) => {
  const targetUrl = `${config.mlServiceUrl}/model-info`;
  const headers = {};
  if (requestId) headers['X-Request-ID'] = requestId;

  try {
    const response = await axios.get(targetUrl, {
      timeout: 3000,
      headers
    });
    return response.data;
  } catch (error) {
    const fs = require('fs');
    const path = require('path');
    const projectRoot = path.resolve(__dirname, '..', '..', '..');

    const loadMeta = (subDir, dataset) => {
      const p = path.join(projectRoot, 'artifacts', subDir, dataset, 'metadata.json');
      if (fs.existsSync(p)) {
        try {
          return JSON.parse(fs.readFileSync(p, 'utf8'));
        } catch (e) {
          return null;
        }
      }
      return null;
    };

    const nslMeta = loadMeta('v1.3', 'nsl_kdd') || loadMeta('remediated', 'nsl_kdd') || loadMeta('production', 'nsl_kdd');
    const cicMeta = loadMeta('v1.2', 'cicids2017') || loadMeta('remediated', 'cicids2017') || loadMeta('production', 'cicids2017');

    return {
      source: 'local_artifact_fallback',
      models: {
        nsl_kdd: {
          dataset: 'NSL-KDD',
          model_name: 'NetShieldNSLKDDExpertEnsembleV13',
          model_version: nslMeta?.model_version || 'NetShield-NSLKDD-ExpertEnsemble-v1.3',
          algorithm: 'Multi-Model Expert Ensemble (Base + Specialists)',
          feature_count: nslMeta?.feature_count || 134,
          accuracy: nslMeta?.evaluation_metrics?.accuracy || 0.8123,
          weighted_f1: nslMeta?.evaluation_metrics?.weighted_f1 || 0.7995,
          provenance: 'Multi-Model Expert Ensemble (Frozen v1.3)'
        },
        cicids2017: {
          dataset: 'CICIDS2017',
          model_name: 'XGBClassifier',
          model_version: cicMeta?.model_version || 'NetShield-CICIDS2017-TwoStage-v1.2',
          algorithm: 'Two-Stage Cascade (Hist XGBoost)',
          feature_count: cicMeta?.feature_count || 56,
          accuracy: cicMeta?.evaluation_metrics?.accuracy || 0.9925,
          weighted_f1: cicMeta?.evaluation_metrics?.weighted_f1 || 0.9930,
          provenance: 'Two-Stage Cascade Holdout (Frozen v1.2)'
        }
      }
    };
  }
};

module.exports = {
  predict,
  checkHealth,
  getModelInfo,
  MLServiceError
};
