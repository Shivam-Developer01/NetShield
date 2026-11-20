"""
NetShield Phase 3: Master Feature Selection Execution Script
Performs correlation analysis, Mutual Information ranking, and Random Forest feature importance
STRICTLY on X_train and y_train. Serializes selectors and feature metadata.
Memory & CPU optimized for 8GB RAM development machine.
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_selection import mutual_info_classif
from sklearn.ensemble import RandomForestClassifier

sys.path.append(os.path.dirname(__file__))
from feature_selector import NetShieldFeatureSelector

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
PROCESSED_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "processed")
ARTIFACTS_DIR = os.path.join(PROJECT_ROOT, "artifacts")


def log(msg):
    print(msg, flush=True)


def remove_highly_correlated_features(X_train, feature_names, threshold=0.98):
    """
    Identifies and returns indices/names of features to keep after removing collinear pairs (|r| > threshold).
    Computed STRICTLY on X_train.
    """
    df = pd.DataFrame(X_train, columns=feature_names)
    corr_matrix = df.corr().abs()
    
    upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
    to_drop = [column for column in upper.columns if any(upper[column] > threshold)]
    
    keep_names = [col for col in feature_names if col not in to_drop]
    keep_indices = [feature_names.index(col) for col in keep_names]
    
    return keep_indices, keep_names, to_drop


def analyze_nsl_kdd():
    log("=" * 60)
    log("EXECUTING NSL-KDD FEATURE SELECTION PIPELINE")
    log("=" * 60)

    train_npz = os.path.join(PROCESSED_DATA_DIR, "nsl_kdd", "train_processed.npz")
    test_npz = os.path.join(PROCESSED_DATA_DIR, "nsl_kdd", "test_processed.npz")
    features_json = os.path.join(ARTIFACTS_DIR, "features", "nsl_kdd_features.json")

    with open(features_json, "r") as f:
        feature_names = json.load(f)

    train_data = np.load(train_npz)
    test_data = np.load(test_npz)

    X_train, y_train = train_data['X'], train_data['y_5class']
    X_test, y_test = test_data['X'], test_data['y_5class']

    log(f"NSL-KDD Baseline Transformed Features: {X_train.shape[1]}")

    # 1. Correlation Analysis
    log("Running Correlation Analysis on X_train (|r| > 0.98 threshold)...")
    corr_indices, corr_names, dropped_corr = remove_highly_correlated_features(X_train, feature_names, threshold=0.98)
    log(f"  - Features dropped due to collinearity ({len(dropped_corr)}): {dropped_corr}")
    log(f"  - Features retained after correlation filter: {len(corr_names)}")

    X_train_corr = X_train[:, corr_indices]

    # Stratified sampling of X_train for fast MI & RF calculations (30,000 rows)
    np.random.seed(42)
    sample_indices = np.random.choice(len(y_train), size=min(30000, len(y_train)), replace=False)
    X_sample = X_train_corr[sample_indices]
    y_sample = y_train[sample_indices]

    # 2. Mutual Information Calculation (STRICTLY on X_train sample)
    log("Calculating Mutual Information scores on X_train sample...")
    mi_scores = mutual_info_classif(X_sample, y_sample, random_state=42)

    # 3. Model-Based Feature Importance (Random Forest on X_train sample)
    log("Calculating Random Forest feature importances on X_train sample...")
    rf = RandomForestClassifier(n_estimators=50, max_depth=12, random_state=42, n_jobs=2)
    rf.fit(X_sample, y_sample)
    rf_scores = rf.feature_importances_

    ranking_df = pd.DataFrame({
        'feature_name': corr_names,
        'original_index': corr_indices,
        'mi_score': mi_scores,
        'rf_score': rf_scores
    })

    mi_norm = (mi_scores - mi_scores.min()) / (mi_scores.max() - mi_scores.min() + 1e-8)
    rf_norm = (rf_scores - rf_scores.min()) / (rf_scores.max() - rf_scores.min() + 1e-8)
    ranking_df['composite_score'] = (mi_norm + rf_norm) / 2.0

    ranking_df = ranking_df.sort_values(by='composite_score', ascending=False).reset_index(drop=True)

    # Select top non-zero/discriminative features (top 50 or composite_score >= 0.02)
    selected_df = ranking_df[ranking_df['composite_score'] >= 0.02].copy()
    if len(selected_df) < 30:
        selected_df = ranking_df.head(45).copy()

    selected_indices = selected_df['original_index'].tolist()
    selected_names = selected_df['feature_name'].tolist()

    log(f"Selected {len(selected_names)} features out of {len(feature_names)} baseline features.")

    selector = NetShieldFeatureSelector(selected_indices=selected_indices, selected_feature_names=selected_names)
    selector.fit(X_train)

    X_train_selected = selector.transform(X_train)
    X_test_selected = selector.transform(X_test)

    log(f"NSL-KDD Selected Shapes: Train={X_train_selected.shape}, Test={X_test_selected.shape}")

    # Save artifacts
    joblib.dump(selector, os.path.join(ARTIFACTS_DIR, "features", "nsl_kdd_feature_selector.joblib"))
    
    with open(os.path.join(ARTIFACTS_DIR, "features", "nsl_kdd_selected_features.json"), "w") as f:
        json.dump(selected_names, f, indent=2)

    ranking_records = ranking_df.to_dict(orient='records')
    with open(os.path.join(ARTIFACTS_DIR, "metadata", "nsl_kdd_feature_importance.json"), "w") as f:
        json.dump(ranking_records, f, indent=2)

    np.savez_compressed(
        os.path.join(PROCESSED_DATA_DIR, "nsl_kdd", "train_reduced.npz"),
        X=X_train_selected.astype(np.float32),
        y_5class=y_train
    )
    np.savez_compressed(
        os.path.join(PROCESSED_DATA_DIR, "nsl_kdd", "test_reduced.npz"),
        X=X_test_selected.astype(np.float32),
        y_5class=test_data['y_5class']
    )

    return {
        "original_features": len(feature_names),
        "collinear_dropped": len(dropped_corr),
        "selected_features_count": len(selected_names),
        "selected_features": selected_names
    }


def analyze_cicids2017():
    log("=" * 60)
    log("EXECUTING CICIDS2017 FEATURE SELECTION PIPELINE")
    log("=" * 60)

    train_npz = os.path.join(PROCESSED_DATA_DIR, "cicids2017", "train_processed.npz")
    test_npz = os.path.join(PROCESSED_DATA_DIR, "cicids2017", "test_processed.npz")
    features_json = os.path.join(ARTIFACTS_DIR, "features", "cicids2017_features.json")

    with open(features_json, "r") as f:
        feature_names = json.load(f)

    log("Loading CICIDS2017 processed train and test sets...")
    train_data = np.load(train_npz)
    test_data = np.load(test_npz)

    X_train, y_train = train_data['X'], train_data['y']
    X_test, y_test = test_data['X'], test_data['y']

    log(f"CICIDS2017 Baseline Transformed Features: {X_train.shape[1]}")

    # Memory-conscious stratified sample of X_train (50,000 rows)
    np.random.seed(42)
    sample_indices = np.random.choice(len(y_train), size=min(50000, len(y_train)), replace=False)
    X_sample = X_train[sample_indices]
    y_sample = y_train[sample_indices]

    # 1. Correlation Analysis (on X_train sample)
    log("Running Correlation Analysis on X_train sample (|r| > 0.98 threshold)...")
    corr_indices, corr_names, dropped_corr = remove_highly_correlated_features(X_sample, feature_names, threshold=0.98)
    log(f"  - Collinear features dropped ({len(dropped_corr)}): {dropped_corr}")
    log(f"  - Features retained after correlation filter: {len(corr_names)}")

    X_sample_corr = X_sample[:, corr_indices]

    # 2. Mutual Information Calculation (STRICTLY on X_train sample)
    log("Calculating Mutual Information scores on X_train sample...")
    mi_scores = mutual_info_classif(X_sample_corr, y_sample, random_state=42)

    # 3. Model-Based Feature Importance (Random Forest on X_train sample)
    log("Calculating Random Forest feature importances on X_train sample...")
    rf = RandomForestClassifier(n_estimators=50, max_depth=12, random_state=42, n_jobs=2)
    rf.fit(X_sample_corr, y_sample)
    rf_scores = rf.feature_importances_

    ranking_df = pd.DataFrame({
        'feature_name': corr_names,
        'original_index': corr_indices,
        'mi_score': mi_scores,
        'rf_score': rf_scores
    })

    mi_norm = (mi_scores - mi_scores.min()) / (mi_scores.max() - mi_scores.min() + 1e-8)
    rf_norm = (rf_scores - rf_scores.min()) / (rf_scores.max() - rf_scores.min() + 1e-8)
    ranking_df['composite_score'] = (mi_norm + rf_norm) / 2.0

    ranking_df = ranking_df.sort_values(by='composite_score', ascending=False).reset_index(drop=True)

    selected_df = ranking_df[ranking_df['composite_score'] >= 0.02].copy()
    if len(selected_df) < 25:
        selected_df = ranking_df.head(35).copy()

    selected_indices = selected_df['original_index'].tolist()
    selected_names = selected_df['feature_name'].tolist()

    log(f"Selected {len(selected_names)} features out of {len(feature_names)} baseline features.")

    selector = NetShieldFeatureSelector(selected_indices=selected_indices, selected_feature_names=selected_names)
    selector.fit(X_train)

    X_train_selected = selector.transform(X_train)
    X_test_selected = selector.transform(X_test)

    log(f"CICIDS2017 Selected Shapes: Train={X_train_selected.shape}, Test={X_test_selected.shape}")

    joblib.dump(selector, os.path.join(ARTIFACTS_DIR, "features", "cicids2017_feature_selector.joblib"))

    with open(os.path.join(ARTIFACTS_DIR, "features", "cicids2017_selected_features.json"), "w") as f:
        json.dump(selected_names, f, indent=2)

    ranking_records = ranking_df.to_dict(orient='records')
    with open(os.path.join(ARTIFACTS_DIR, "metadata", "cicids2017_feature_importance.json"), "w") as f:
        json.dump(ranking_records, f, indent=2)

    np.savez_compressed(
        os.path.join(PROCESSED_DATA_DIR, "cicids2017", "train_reduced.npz"),
        X=X_train_selected.astype(np.float32),
        y=y_train
    )
    np.savez_compressed(
        os.path.join(PROCESSED_DATA_DIR, "cicids2017", "test_reduced.npz"),
        X=X_test_selected.astype(np.float32),
        y=y_test
    )

    return {
        "original_features": len(feature_names),
        "collinear_dropped": len(dropped_corr),
        "selected_features_count": len(selected_names),
        "selected_features": selected_names
    }


def main():
    nsl_res = analyze_nsl_kdd()
    cic_res = analyze_cicids2017()

    meta = {
        "nsl_kdd": nsl_res,
        "cicids2017": cic_res,
        "leakage_prevention": "Strictly calculated on X_train only",
        "correlation_threshold": 0.98,
        "random_state": 42
    }

    with open(os.path.join(ARTIFACTS_DIR, "metadata", "feature_selection_metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)

    log("=" * 60)
    log("ALL FEATURE SELECTION PIPELINES EXECUTED SUCCESSFULLY.")
    log("=" * 60)


if __name__ == "__main__":
    main()
