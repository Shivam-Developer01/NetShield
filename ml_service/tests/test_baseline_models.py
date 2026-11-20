"""
NetShield Phase 4 Validation Test Suite
Automated tests verifying baseline model serialization, reloading, prediction shapes, and zero NaNs.
Adapted to run both in full-dataset local development and in lightweight CI/fresh-clone environments.
"""

import os
import sys
import json
import joblib
import numpy as np

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PROCESSED_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "processed")
ARTIFACTS_DIR = os.path.join(PROJECT_ROOT, "artifacts")
BASELINE_DIR = os.path.join(ARTIFACTS_DIR, "models", "baseline")
METADATA_DIR = os.path.join(ARTIFACTS_DIR, "metadata")

sys.path.append(os.path.dirname(__file__))
from fixtures.sample_traffic import get_nsl_kdd_reduced_array, get_cicids2017_reduced_array


def test_nsl_kdd_baseline_models():
    """1. Verify NSL-KDD baseline models reload and produce valid predictions."""
    model_names = [
        "nsl_kdd_logistic_regression.joblib",
        "nsl_kdd_decision_tree.joblib",
        "nsl_kdd_gaussian_naive_bayes.joblib"
    ]

    test_npz = os.path.join(PROCESSED_DATA_DIR, "nsl_kdd", "test_reduced.npz")
    if os.path.exists(test_npz):
        test_data = np.load(test_npz)
        X_test = test_data['X']
    else:
        X_test = get_nsl_kdd_reduced_array(50)

    assert X_test.shape[1] == 37, f"Expected 37 features for NSL-KDD reduced set, got {X_test.shape[1]}"

    for m_file in model_names:
        m_path = os.path.join(BASELINE_DIR, m_file)
        assert os.path.exists(m_path), f"Baseline model file missing: {m_file}"

        model = joblib.load(m_path)
        assert hasattr(model, "predict"), f"Loaded object {m_file} is not a valid predictor!"

        preds = model.predict(X_test)
        assert len(preds) == len(X_test), f"Prediction count mismatch for {m_file}"
        assert not np.isnan(preds).any(), f"NaN predictions detected for {m_file}"


def test_cicids2017_baseline_models():
    """2. Verify CICIDS2017 baseline models reload and produce valid predictions."""
    model_names = [
        "cicids2017_logistic_regression.joblib",
        "cicids2017_decision_tree.joblib",
        "cicids2017_gaussian_naive_bayes.joblib"
    ]

    test_npz = os.path.join(PROCESSED_DATA_DIR, "cicids2017", "test_reduced.npz")
    if os.path.exists(test_npz):
        test_data = np.load(test_npz)
        X_test = test_data['X'][:1000]
    else:
        X_test = get_cicids2017_reduced_array(50)

    assert X_test.shape[1] == 43, f"Expected 43 features for CICIDS2017 reduced set, got {X_test.shape[1]}"

    for m_file in model_names:
        m_path = os.path.join(BASELINE_DIR, m_file)
        assert os.path.exists(m_path), f"Baseline model file missing: {m_file}"

        model = joblib.load(m_path)
        assert hasattr(model, "predict"), f"Loaded object {m_file} is not a valid predictor!"

        preds = model.predict(X_test)
        assert len(preds) == len(X_test), f"Prediction count mismatch for {m_file}"
        assert not np.isnan(preds).any(), f"NaN predictions detected for {m_file}"


def test_baseline_eval_metadata():
    """3. Verify baseline evaluation JSON metadata exists and contains required fields."""
    meta_files = [
        "nsl_kdd_baseline_eval.json",
        "cicids2017_baseline_eval.json",
        "baseline_models_metadata.json"
    ]

    for m_file in meta_files:
        m_path = os.path.join(METADATA_DIR, m_file)
        assert os.path.exists(m_path), f"Baseline metadata file missing: {m_file}"

        with open(m_path, "r") as f:
            data = json.load(f)
        assert isinstance(data, dict), f"Metadata in {m_file} must be a valid JSON object"
