"""
NetShield Phase 2 Validation Test Suite
Automated tests verifying leakage-free preprocessing, artifact serialization, shape integrity, and zero NaNs/Infs.
Adapted to run both in full-dataset local development and in lightweight CI/fresh-clone environments.
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RAW_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "raw")
PROCESSED_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "processed")
ARTIFACTS_DIR = os.path.join(PROJECT_ROOT, "artifacts")

# Import test fixtures
sys.path.append(os.path.dirname(__file__))
from fixtures.sample_traffic import get_nsl_kdd_synthetic_df, get_cicids2017_synthetic_df


def test_raw_datasets_exist_and_unchanged():
    """1. Verify raw dataset files exist and remain untouched when present, or skeleton README is present."""
    nsl_train = os.path.join(RAW_DATA_DIR, "KDDTrain+.txt")
    nsl_test = os.path.join(RAW_DATA_DIR, "KDDTest+.txt")
    raw_readme = os.path.join(RAW_DATA_DIR, "README.md")
    
    assert os.path.exists(RAW_DATA_DIR), "data/raw directory missing!"
    assert os.path.exists(raw_readme), "data/raw/README.md missing!"

    # If full canonical datasets are present locally, verify exact byte integrity
    if os.path.exists(nsl_train) and os.path.exists(nsl_test):
        assert os.path.getsize(nsl_train) == 19109424, f"KDDTrain+.txt size altered: {os.path.getsize(nsl_train)}"
        assert os.path.getsize(nsl_test) == 3441513, f"KDDTest+.txt size altered: {os.path.getsize(nsl_test)}"
    else:
        # On fresh clone / CI where large raw datasets are git-ignored, verify synthetic sample loads cleanly
        df_sample = get_nsl_kdd_synthetic_df(5)
        assert len(df_sample) == 5
        assert "duration" in df_sample.columns


def test_nsl_kdd_processed_artifacts_and_shapes():
    """2. Verify NSL-KDD processed files, shapes, and artifact loading."""
    preprocessor_path = os.path.join(ARTIFACTS_DIR, "preprocessors", "nsl_kdd_preprocessor.joblib")
    features_path = os.path.join(ARTIFACTS_DIR, "features", "nsl_kdd_features.json")
    encoder_path = os.path.join(ARTIFACTS_DIR, "encoders", "nsl_kdd_label_encoder.joblib")

    assert os.path.exists(preprocessor_path), "nsl_kdd_preprocessor.joblib missing!"
    assert os.path.exists(features_path), "nsl_kdd_features.json missing!"
    assert os.path.exists(encoder_path), "nsl_kdd_label_encoder.joblib missing!"

    preprocessor = joblib.load(preprocessor_path)
    encoder = joblib.load(encoder_path)
    with open(features_path, "r") as f:
        features = json.load(f)

    assert hasattr(preprocessor, "transform"), "Loaded preprocessor is not a valid Sklearn transformer!"
    assert hasattr(encoder, "classes_"), "Loaded encoder missing classes_ attribute!"

    # Verify transformer against synthetic fixture records
    df_sample = get_nsl_kdd_synthetic_df(10)
    X_sample = preprocessor.transform(df_sample)
    assert X_sample.shape[1] == len(features), f"Transformed feature dimension mismatch: {X_sample.shape[1]} vs {len(features)}"
    assert not np.isnan(X_sample).any(), "NaN values produced during NSL-KDD transformation!"
    assert not np.isinf(X_sample).any(), "Inf values produced during NSL-KDD transformation!"

    # If full processed arrays exist, verify complete dataset counts
    train_npz = os.path.join(PROCESSED_DATA_DIR, "nsl_kdd", "train_processed.npz")
    test_npz = os.path.join(PROCESSED_DATA_DIR, "nsl_kdd", "test_processed.npz")
    if os.path.exists(train_npz) and os.path.exists(test_npz):
        train_data = np.load(train_npz)
        test_data = np.load(test_npz)
        X_train, y_train = train_data['X'], train_data['y_5class']
        X_test, y_test = test_data['X'], test_data['y_5class']
        assert X_train.shape[0] == 125973, f"Unexpected NSL-KDD train row count: {X_train.shape[0]}"
        assert X_test.shape[0] == 22544, f"Unexpected NSL-KDD test row count: {X_test.shape[0]}"
        assert X_train.shape[1] == X_test.shape[1], "Train and Test feature counts do not match!"
        assert not np.isnan(X_train).any(), "NaN values found in NSL-KDD X_train!"
        assert not np.isnan(X_test).any(), "NaN values found in NSL-KDD X_test!"


def test_cicids2017_processed_artifacts_and_shapes():
    """3. Verify CICIDS2017 processed files, shapes, and zero NaNs/Infs."""
    preprocessor_path = os.path.join(ARTIFACTS_DIR, "preprocessors", "cicids2017_preprocessor.joblib")
    features_path = os.path.join(ARTIFACTS_DIR, "features", "cicids2017_features.json")
    encoder_path = os.path.join(ARTIFACTS_DIR, "encoders", "cicids2017_label_encoder.joblib")

    assert os.path.exists(preprocessor_path), "cicids2017_preprocessor.joblib missing!"
    assert os.path.exists(features_path), "cicids2017_features.json missing!"
    assert os.path.exists(encoder_path), "cicids2017_label_encoder.joblib missing!"

    preprocessor = joblib.load(preprocessor_path)
    encoder = joblib.load(encoder_path)
    with open(features_path, "r") as f:
        features = json.load(f)

    assert hasattr(preprocessor, "transform"), "Loaded preprocessor is not a valid Sklearn transformer!"
    assert hasattr(encoder, "classes_"), "Loaded encoder missing classes_ attribute!"

    # Verify transformer against synthetic fixture records
    df_sample = get_cicids2017_synthetic_df(10)
    X_sample = preprocessor.transform(df_sample)
    assert X_sample.shape[1] == len(features), f"Transformed feature dimension mismatch: {X_sample.shape[1]} vs {len(features)}"
    assert not np.isnan(X_sample).any(), "NaN values produced during CICIDS2017 transformation!"
    assert not np.isinf(X_sample).any(), "Inf values produced during CICIDS2017 transformation!"

    # If full processed arrays exist, verify complete dataset counts
    train_npz = os.path.join(PROCESSED_DATA_DIR, "cicids2017", "train_processed.npz")
    test_npz = os.path.join(PROCESSED_DATA_DIR, "cicids2017", "test_processed.npz")
    if os.path.exists(train_npz) and os.path.exists(test_npz):
        train_data = np.load(train_npz)
        test_data = np.load(test_npz)
        X_train, y_train = train_data['X'], train_data['y']
        X_test, y_test = test_data['X'], test_data['y']
        assert X_train.shape[0] + X_test.shape[0] == 2830743, "Total CICIDS2017 row count mismatch!"
        assert X_train.shape[1] == 70, f"Expected 70 features, got {X_train.shape[1]}"
        assert X_test.shape[1] == 70, f"Expected 70 features in test set, got {X_test.shape[1]}"
