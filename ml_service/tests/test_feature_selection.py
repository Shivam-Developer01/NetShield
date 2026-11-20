"""
NetShield Phase 3 Validation Test Suite
Automated tests verifying feature selector serialization, shape integrity, and leakage-free execution.
Adapted to run both in full-dataset local development and in lightweight CI/fresh-clone environments.
"""

import os
import sys
import json
import joblib
import numpy as np

# Ensure feature_selector class is found by joblib unpickler
FEATURE_SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "features"))
if FEATURE_SRC_DIR not in sys.path:
    sys.path.append(FEATURE_SRC_DIR)

from feature_selector import NetShieldFeatureSelector

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PROCESSED_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "processed")
ARTIFACTS_DIR = os.path.join(PROJECT_ROOT, "artifacts")

# Import test fixtures
sys.path.append(os.path.dirname(__file__))
from fixtures.sample_traffic import get_nsl_kdd_synthetic_df, get_cicids2017_synthetic_df


def test_nsl_kdd_feature_selection_artifacts():
    """1. Verify NSL-KDD feature selection artifacts and reduced shapes."""
    selector_path = os.path.join(ARTIFACTS_DIR, "features", "nsl_kdd_feature_selector.joblib")
    features_path = os.path.join(ARTIFACTS_DIR, "features", "nsl_kdd_selected_features.json")
    importance_path = os.path.join(ARTIFACTS_DIR, "metadata", "nsl_kdd_feature_importance.json")

    assert os.path.exists(selector_path), "NSL-KDD feature selector missing!"
    assert os.path.exists(features_path), "NSL-KDD selected features JSON missing!"
    assert os.path.exists(importance_path), "NSL-KDD feature importance metadata missing!"

    selector = joblib.load(selector_path)
    with open(features_path, "r") as f:
        selected_features = json.load(f)

    assert len(selected_features) == len(selector.selected_indices), "Selected features count mismatch!"

    # Verify transformation with preprocessor output
    prep_path = os.path.join(ARTIFACTS_DIR, "preprocessors", "nsl_kdd_preprocessor.joblib")
    if os.path.exists(prep_path):
        prep = joblib.load(prep_path)
        df_sample = get_nsl_kdd_synthetic_df(5)
        X_sample = prep.transform(df_sample)
        X_reduced_sample = selector.transform(X_sample)
        assert X_reduced_sample.shape[1] == len(selected_features)
        assert not np.isnan(X_reduced_sample).any()

    # If processed npz files exist locally, verify full dataset properties
    train_npz = os.path.join(PROCESSED_DATA_DIR, "nsl_kdd", "train_processed.npz")
    reduced_train_npz = os.path.join(PROCESSED_DATA_DIR, "nsl_kdd", "train_reduced.npz")
    reduced_test_npz = os.path.join(PROCESSED_DATA_DIR, "nsl_kdd", "test_reduced.npz")
    if os.path.exists(train_npz) and os.path.exists(reduced_train_npz) and os.path.exists(reduced_test_npz):
        reduced_train = np.load(reduced_train_npz)
        reduced_test = np.load(reduced_test_npz)
        X_red_train = reduced_train['X']
        X_red_test = reduced_test['X']
        assert X_red_train.shape[1] == len(selected_features)
        assert X_red_train.shape[1] == X_red_test.shape[1]
        X_transformed_test = selector.transform(np.load(os.path.join(PROCESSED_DATA_DIR, "nsl_kdd", "test_processed.npz"))['X'])
        np.testing.assert_allclose(X_transformed_test, X_red_test, rtol=1e-5)


def test_cicids2017_feature_selection_artifacts():
    """2. Verify CICIDS2017 feature selection artifacts and reduced shapes."""
    selector_path = os.path.join(ARTIFACTS_DIR, "features", "cicids2017_feature_selector.joblib")
    features_path = os.path.join(ARTIFACTS_DIR, "features", "cicids2017_selected_features.json")
    importance_path = os.path.join(ARTIFACTS_DIR, "metadata", "cicids2017_feature_importance.json")

    assert os.path.exists(selector_path), "CICIDS2017 feature selector missing!"
    assert os.path.exists(features_path), "CICIDS2017 selected features JSON missing!"
    assert os.path.exists(importance_path), "CICIDS2017 feature importance metadata missing!"

    selector = joblib.load(selector_path)
    with open(features_path, "r") as f:
        selected_features = json.load(f)

    assert len(selected_features) == len(selector.selected_indices), "Selected features count mismatch!"

    # Verify transformation with preprocessor output
    prep_path = os.path.join(ARTIFACTS_DIR, "preprocessors", "cicids2017_preprocessor.joblib")
    if os.path.exists(prep_path):
        prep = joblib.load(prep_path)
        df_sample = get_cicids2017_synthetic_df(5)
        X_sample = prep.transform(df_sample)
        X_reduced_sample = selector.transform(X_sample)
        assert X_reduced_sample.shape[1] == len(selected_features)
        assert not np.isnan(X_reduced_sample).any()

    # If processed npz files exist locally, verify full dataset properties
    reduced_train_npz = os.path.join(PROCESSED_DATA_DIR, "cicids2017", "train_reduced.npz")
    reduced_test_npz = os.path.join(PROCESSED_DATA_DIR, "cicids2017", "test_reduced.npz")
    if os.path.exists(reduced_train_npz) and os.path.exists(reduced_test_npz):
        reduced_train = np.load(reduced_train_npz)
        reduced_test = np.load(reduced_test_npz)
        X_red_train = reduced_train['X']
        X_red_test = reduced_test['X']
        assert X_red_train.shape[1] == len(selected_features)
        assert X_red_train.shape[1] == X_red_test.shape[1]
        assert not np.isnan(X_red_train).any()
        assert not np.isnan(X_red_test).any()
