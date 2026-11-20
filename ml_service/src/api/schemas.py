"""
NetShield FastAPI Schemas
Pydantic V2 models for request validation, error responses, and output formatting.
"""

import math
from typing import Dict, Any, List, Union, Optional
from pydantic import BaseModel, Field, field_validator


class HealthResponse(BaseModel):
    status: str = Field(..., description="Service status: 'healthy' or 'degraded'")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp")
    loaded_datasets: List[str] = Field(..., description="List of ready production dataset models")


class ModelDetail(BaseModel):
    dataset: str
    model_name: str
    model_version: str
    algorithm: str
    feature_count: int
    training_samples: int
    accuracy: float
    weighted_f1: float
    status: str


class ModelInfoResponse(BaseModel):
    models: Dict[str, ModelDetail]


class PredictRequest(BaseModel):
    dataset_type: str = Field(..., description="Dataset model pipeline to use: 'nsl_kdd' or 'cicids2017'")
    input_data: Union[Dict[str, Any], List[Dict[str, Any]]] = Field(
        ...,
        description="Raw feature record (dict) or batch of records (list of dicts)"
    )

    @field_validator("dataset_type")
    @classmethod
    def validate_dataset_type(cls, v: str) -> str:
        cleaned = v.lower().replace("-", "_").strip()
        if cleaned not in ["nsl_kdd", "cicids2017"]:
            raise ValueError("Unsupported dataset_type. Allowed values are 'nsl_kdd' or 'cicids2017'.")
        return cleaned

    @field_validator("input_data")
    @classmethod
    def validate_input_data(cls, v: Union[Dict[str, Any], List[Dict[str, Any]]]) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        records = [v] if isinstance(v, dict) else v

        if not records:
            raise ValueError("input_data cannot be empty.")

        for rec_idx, rec in enumerate(records):
            if not isinstance(rec, dict):
                raise ValueError(f"Record at index {rec_idx} must be a valid JSON dictionary.")
            if not rec:
                raise ValueError(f"Record at index {rec_idx} cannot be an empty dictionary.")

            for key, val in rec.items():
                if isinstance(val, (int, float)):
                    if math.isnan(val) or math.isinf(val):
                        raise ValueError(f"Invalid numeric value '{val}' (NaN or Infinity) detected in field '{key}' at index {rec_idx}.")

        return v


class SinglePrediction(BaseModel):
    record_index: int
    prediction: str
    prediction_index: int
    confidence: float = Field(..., description="Confidence probability score (0.0 to 1.0)")
    class_probabilities: Dict[str, float]


class PredictResponse(BaseModel):
    dataset_type: str
    model_version: str
    records_processed: int
    predictions: List[SinglePrediction]


class ErrorResponse(BaseModel):
    error: str
    message: str
    details: Optional[Any] = None
