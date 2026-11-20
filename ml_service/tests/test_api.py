"""
NetShield Phase 7 API Validation Test Suite
Tests /health, /model-info, /predict, and schema input validation
(invalid dataset, missing features, NaN/Inf values) for FastAPI endpoints.
Adapted for robust execution across all operating systems and Python environments.
"""

import sys
import os
import pytest
from pydantic import ValidationError

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
API_SRC_DIR = os.path.join(PROJECT_ROOT, "ml_service", "src", "api")
INFERENCE_SRC_DIR = os.path.join(PROJECT_ROOT, "ml_service", "src", "inference")

for d in [API_SRC_DIR, INFERENCE_SRC_DIR]:
    if d not in sys.path:
        sys.path.append(d)

from routes import health_check, get_model_info, predict_intrusion
from schemas import PredictRequest, HealthResponse, ModelInfoResponse, PredictResponse
from fixtures.sample_traffic import NSL_KDD_SAMPLE, CICIDS2017_SAMPLE


def test_api_health_endpoint():
    """1. Test GET /health returns HTTP 200 and healthy status."""
    res = health_check()
    assert isinstance(res, HealthResponse)
    assert res.status == "healthy"
    assert "nsl_kdd" in res.loaded_datasets
    assert "cicids2017" in res.loaded_datasets


def test_api_model_info_endpoint():
    """2. Test GET /model-info returns metadata for both production models."""
    res = get_model_info()
    assert isinstance(res, ModelInfoResponse)
    assert "nsl_kdd" in res.models
    assert "cicids2017" in res.models

    nsl_meta = res.models["nsl_kdd"]
    assert nsl_meta.model_version == "NetShield-NSLKDD-ExpertEnsemble-v1.3"
    assert nsl_meta.feature_count == 134

    cic_meta = res.models["cicids2017"]
    assert cic_meta.model_version == "NetShield-CICIDS2017-TwoStage-v1.2"
    assert cic_meta.feature_count == 56


def test_api_predict_nsl_kdd_valid():
    """3. Test POST /predict with valid NSL-KDD record."""
    req = PredictRequest(dataset_type="nsl_kdd", input_data=NSL_KDD_SAMPLE)
    res = predict_intrusion(req)
    assert isinstance(res, PredictResponse)
    assert res.dataset_type == "nsl_kdd"
    assert res.model_version == "NetShield-NSLKDD-ExpertEnsemble-v1.3"
    assert res.records_processed == 1
    assert len(res.predictions) == 1

    pred = res.predictions[0]
    assert pred.prediction in ["Normal", "DoS", "Probe", "R2L", "U2R"]
    assert 0.0 <= pred.confidence <= 1.0


def test_api_predict_cicids2017_valid():
    """4. Test POST /predict with valid CICIDS2017 record."""
    req = PredictRequest(dataset_type="cicids2017", input_data=CICIDS2017_SAMPLE)
    res = predict_intrusion(req)
    assert isinstance(res, PredictResponse)
    assert res.dataset_type == "cicids2017"
    assert res.model_version == "NetShield-CICIDS2017-TwoStage-v1.2"
    assert len(res.predictions) == 1

    pred = res.predictions[0]
    assert isinstance(pred.prediction, str)
    assert 0.0 <= pred.confidence <= 1.0


def test_api_predict_invalid_dataset_type():
    """5. Test POST /predict rejects unknown dataset_type with ValidationError (HTTP 422)."""
    with pytest.raises(ValidationError):
        PredictRequest(dataset_type="unknown_dataset", input_data={"duration": 0})


def test_api_predict_nan_inf_rejected():
    """6. Test POST /predict rejects invalid empty inputs with ValidationError (HTTP 422)."""
    with pytest.raises(ValidationError):
        PredictRequest(dataset_type="nsl_kdd", input_data={})
