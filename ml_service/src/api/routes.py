"""
NetShield FastAPI Endpoint Routes
Defines GET /health, GET /model-info, and POST /predict endpoints.
"""

import sys
import os
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status

# Ensure inference pipeline is importable
INFERENCE_SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "inference"))
if INFERENCE_SRC_DIR not in sys.path:
    sys.path.append(INFERENCE_SRC_DIR)

from pipeline import get_inference_pipeline
from schemas import (
    HealthResponse,
    ModelInfoResponse,
    ModelDetail,
    PredictRequest,
    PredictResponse,
    ErrorResponse
)

router = APIRouter()

# Global in-memory metrics for FastAPI ML service
ML_METRICS = {
    "requests_total": 0,
    "failures_total": 0,
    "durations_ms": [],
    "dataset_usage": {"nsl_kdd": 0, "cicids2017": 0}
}


@router.get(
    "/live",
    status_code=status.HTTP_200_OK,
    summary="Liveness check",
    description="Confirms FastAPI process event loop is alive."
)
def liveness_check():
    return {"status": "alive", "service": "netshield-ml-service", "timestamp": datetime.now(timezone.utc).isoformat()}


@router.get(
    "/ready",
    status_code=status.HTTP_200_OK,
    summary="Readiness check",
    description="Checks whether production model bundles are loaded and ready."
)
def readiness_check():
    try:
        pipeline = get_inference_pipeline()
        loaded = list(pipeline.bundles.keys())
        if len(loaded) >= 2:
            return {"status": "ready", "loaded_models": loaded, "timestamp": datetime.now(timezone.utc).isoformat()}
        return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Not all models loaded")
    except Exception:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Model pipeline unavailable")


@router.get(
    "/metrics",
    status_code=status.HTTP_200_OK,
    summary="Prometheus ML operational metrics"
)
def metrics():
    import statistics
    lats = ML_METRICS["durations_ms"]
    avg_lat = round(statistics.mean(lats), 2) if lats else 0.0
    p95_lat = round(sorted(lats)[min(int(len(lats) * 0.95), len(lats) - 1)], 2) if lats else 0.0

    lines = [
        "# HELP netshield_ml_service_requests_total Total inference requests processed by FastAPI",
        "# TYPE netshield_ml_service_requests_total counter",
        f"netshield_ml_service_requests_total {ML_METRICS['requests_total']}",
        "# HELP netshield_ml_service_failures_total Total inference failures in FastAPI",
        "# TYPE netshield_ml_service_failures_total counter",
        f"netshield_ml_service_failures_total {ML_METRICS['failures_total']}",
        "# HELP netshield_ml_service_duration_ms_avg Average ML inference duration in ms",
        "# TYPE netshield_ml_service_duration_ms_avg gauge",
        f"netshield_ml_service_duration_ms_avg {avg_lat}",
        "# HELP netshield_ml_service_duration_ms_p95 p95 ML inference duration in ms",
        "# TYPE netshield_ml_service_duration_ms_p95 gauge",
        f"netshield_ml_service_duration_ms_p95 {p95_lat}"
    ]
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(content="\n".join(lines) + "\n")


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Health check endpoint",
    description="Returns the status of the NetShield ML service and verifies production model loading."
)
def health_check():
    try:
        pipeline = get_inference_pipeline()
        loaded = list(pipeline.bundles.keys())
        if len(loaded) >= 2:
            return HealthResponse(
                status="healthy",
                timestamp=datetime.now(timezone.utc).isoformat(),
                loaded_datasets=loaded
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="ML service is running in degraded mode: Not all production models are loaded."
            )
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML Service is unavailable: Unable to access production model artifacts."
        )


@router.get(
    "/model-info",
    response_model=ModelInfoResponse,
    status_code=status.HTTP_200_OK,
    summary="Production model metadata",
    description="Returns detailed metadata, versions, feature counts, and accuracy metrics for all loaded production models."
)
def get_model_info():
    try:
        pipeline = get_inference_pipeline()
        models_dict = {}

        for dataset_key, bundle in pipeline.bundles.items():
            meta = bundle["metadata"]
            eval_metrics = meta.get("evaluation_metrics", {})
            models_dict[dataset_key] = ModelDetail(
                dataset=meta.get("dataset", dataset_key.upper()),
                model_name=str(bundle["model"].__class__.__name__),
                model_version=meta.get("model_version", "v1.0"),
                algorithm=meta.get("algorithm", "XGBoost Classifier"),
                feature_count=meta.get("feature_count") or len(bundle.get("schema", [])),
                training_samples=meta.get("training_samples", 0),
                accuracy=float(eval_metrics.get("accuracy", 0.0)),
                weighted_f1=float(eval_metrics.get("weighted_f1") or eval_metrics.get("f1_weighted", 0.0)),
                status="active"
            )

        return ModelInfoResponse(models=models_dict)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve model information metadata."
        )


@router.post(
    "/predict",
    response_model=PredictResponse,
    status_code=status.HTTP_200_OK,
    summary="Real-time and batch intrusion prediction",
    description="Executes the complete 5-step ML pipeline (raw features -> preprocessor -> feature selector -> XGBoost model -> label decoder) for NSL-KDD or CICIDS2017."
)
def predict_intrusion(request: PredictRequest):
    import time
    t0 = time.time()
    ML_METRICS["requests_total"] += 1
    if request.dataset_type in ML_METRICS["dataset_usage"]:
        ML_METRICS["dataset_usage"][request.dataset_type] += 1

    try:
        pipeline = get_inference_pipeline()
        results = pipeline.predict(request.dataset_type, request.input_data)
        elapsed = (time.time() - t0) * 1000
        ML_METRICS["durations_ms"].append(elapsed)
        if len(ML_METRICS["durations_ms"]) > 500:
            ML_METRICS["durations_ms"].pop(0)
        return PredictResponse(**results)
    except ValueError as ve:
        ML_METRICS["failures_total"] += 1
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Inference Validation Error: {str(ve)}"
        )
    except KeyError as ke:
        ML_METRICS["failures_total"] += 1
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Missing Required Feature Field: {str(ke)}"
        )
    except Exception as e:
        ML_METRICS["failures_total"] += 1
        # Sanitize exception message to prevent stack trace or filesystem exposure
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal error occurred while processing the inference request."
        )
