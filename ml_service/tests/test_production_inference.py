"""
NetShield Phase 6 Validation Test Suite
Automated end-to-end tests verifying production model loading, complete 5-step inference chain,
label decoding, confidence scores, zero NaNs, and dataset-specific routing.
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PROCESSED_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "processed")
ARTIFACTS_DIR = os.path.join(PROJECT_ROOT, "artifacts")
PRODUCTION_DIR = os.path.join(ARTIFACTS_DIR, "production")

# Ensure inference module is importable
INFERENCE_SRC_DIR = os.path.join(PROJECT_ROOT, "ml_service", "src", "inference")
if INFERENCE_SRC_DIR not in sys.path:
    sys.path.append(INFERENCE_SRC_DIR)

from pipeline import get_inference_pipeline, NetShieldInferencePipeline


def test_production_artifacts_exist():
    """1. Verify that all dataset-specific production artifacts exist in artifacts/production/."""
    for dataset in ["nsl_kdd", "cicids2017"]:
        d_dir = os.path.join(PRODUCTION_DIR, dataset)
        assert os.path.exists(d_dir), f"Production directory missing for {dataset}"

        required_files = [
            "best_model.joblib",
            "preprocessor.joblib",
            "feature_selector.joblib",
            "label_encoder.joblib",
            "feature_schema.json",
            "metadata.json"
        ]
        for fname in required_files:
            fpath = os.path.join(d_dir, fname)
            assert os.path.exists(fpath), f"Production artifact missing: {dataset}/{fname}"


def test_nsl_kdd_end_to_end_production_inference():
    """2. Verify NSL-KDD complete production inference pipeline execution."""
    pipeline = get_inference_pipeline()

    sample_dict = {
        "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF",
        "src_bytes": 215, "dst_bytes": 4507, "land": 0, "wrong_fragment": 0,
        "urgent": 0, "hot": 0, "num_failed_logins": 0, "logged_in": 1,
        "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0,
        "num_file_creations": 0, "num_shells": 0, "num_access_files": 0,
        "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0,
        "count": 1, "srv_count": 1, "serror_rate": 0.0, "srv_serror_rate": 0.0,
        "rerror_rate": 0.0, "srv_rerror_rate": 0.0, "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0, "dst_host_count": 255,
        "dst_host_srv_count": 255, "dst_host_same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0.0, "dst_host_same_src_port_rate": 0.0,
        "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 0.0,
        "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 0.0,
        "dst_host_srv_rerror_rate": 0.0
    }

    res = pipeline.predict("nsl_kdd", sample_dict)

    assert res["dataset_type"] == "nsl_kdd"
    assert res["records_processed"] == 1
    assert len(res["predictions"]) == 1

    pred_obj = res["predictions"][0]
    assert pred_obj["prediction"] in ["Normal", "DoS", "Probe", "R2L", "U2R"]
    assert 0.0 <= pred_obj["confidence"] <= 1.0
    assert not np.isnan(pred_obj["confidence"])


def test_cicids2017_end_to_end_production_inference():
    """3. Verify CICIDS2017 complete production inference pipeline execution."""
    pipeline = get_inference_pipeline()

    raw_csv_path = os.path.join(PROJECT_ROOT, "data", "raw", "Monday-WorkingHours.pcap_ISCX.csv")
    if os.path.exists(raw_csv_path):
        df_sample = pd.read_csv(raw_csv_path, nrows=5)
        feature_cols = [c for c in df_sample.columns if c.strip() != "Label"]
        df_features = df_sample[feature_cols]
    else:
        sys.path.append(os.path.dirname(__file__))
        from fixtures.sample_traffic import get_cicids2017_synthetic_df
        df_features = get_cicids2017_synthetic_df(5)

    res = pipeline.predict("cicids2017", df_features)

    assert res["dataset_type"] == "cicids2017"
    assert res["records_processed"] == 5
    assert len(res["predictions"]) == 5

    for pred_obj in res["predictions"]:
        assert isinstance(pred_obj["prediction"], str)
        assert 0.0 <= pred_obj["confidence"] <= 1.0
        assert not np.isnan(pred_obj["confidence"])
