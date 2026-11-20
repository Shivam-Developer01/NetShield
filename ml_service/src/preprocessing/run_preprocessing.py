"""
NetShield Phase 2: Master Preprocessing Execution Script
Orchestrates leakage-free preprocessing, artifact serialization, and processed dataset export.
Memory-optimized with float32 downcasting for 8GB RAM development machine.
"""

import os
import sys
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

# Ensure local imports resolve
sys.path.append(os.path.dirname(__file__))

from nsl_kdd_preprocessor import NSLKDDPreprocessor, NSL_KDD_COLUMNS
from cicids2017_preprocessor import CICIDS2017Preprocessor, CONSTANT_FEATURES_CICIDS2017

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

RAW_DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "raw"))
PROCESSED_DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "processed"))
ARTIFACTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "artifacts"))

CICIDS2017_FILES = [
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv"
]


def log(msg):
    print(msg, flush=True)


def process_nsl_kdd():
    log("=" * 60)
    log("EXECUTING NSL-KDD PREPROCESSING PIPELINE")
    log("=" * 60)

    train_path = os.path.join(RAW_DATA_DIR, "KDDTrain+.txt")
    test_path = os.path.join(RAW_DATA_DIR, "KDDTest+.txt")

    log("Loading raw NSL-KDD train and test sets...")
    df_train = pd.read_csv(train_path, header=None, names=NSL_KDD_COLUMNS)
    df_test = pd.read_csv(test_path, header=None, names=NSL_KDD_COLUMNS)

    preprocessor = NSLKDDPreprocessor()

    log("Fitting preprocessor STRICTLY on KDDTrain+...")
    X_train_trans, y_train_5class, y_train_raw, X_train_raw = preprocessor.fit_transform_train(df_train)

    log("Transforming KDDTest+ using fitted preprocessor...")
    X_test_trans, y_test_5class, y_test_raw, X_test_raw = preprocessor.transform_test(df_test)

    log(f"NSL-KDD Transformed Shapes:")
    log(f"  - Train X: {X_train_trans.shape}, y (5-class): {y_train_5class.shape}")
    log(f"  - Test X: {X_test_trans.shape}, y (5-class): {y_test_5class.shape}")
    log(f"  - Total Transformed Features: {len(preprocessor.feature_names)}")

    nsl_dir = os.path.join(PROCESSED_DATA_DIR, "nsl_kdd")
    os.makedirs(nsl_dir, exist_ok=True)
    os.makedirs(os.path.join(ARTIFACTS_DIR, "preprocessors"), exist_ok=True)
    os.makedirs(os.path.join(ARTIFACTS_DIR, "encoders"), exist_ok=True)
    os.makedirs(os.path.join(ARTIFACTS_DIR, "features"), exist_ok=True)

    joblib.dump(preprocessor.column_transformer, os.path.join(ARTIFACTS_DIR, "preprocessors", "nsl_kdd_preprocessor.joblib"))
    joblib.dump(preprocessor.label_encoder_5class, os.path.join(ARTIFACTS_DIR, "encoders", "nsl_kdd_label_encoder.joblib"))
    
    with open(os.path.join(ARTIFACTS_DIR, "features", "nsl_kdd_features.json"), "w") as f:
        json.dump(preprocessor.feature_names, f, indent=2)

    np.savez_compressed(
        os.path.join(nsl_dir, "train_processed.npz"),
        X=X_train_trans.astype(np.float32),
        y_5class=y_train_5class,
        y_raw=y_train_raw
    )

    np.savez_compressed(
        os.path.join(nsl_dir, "test_processed.npz"),
        X=X_test_trans.astype(np.float32),
        y_5class=y_test_5class,
        y_raw=y_test_raw
    )

    log("NSL-KDD Preprocessing Complete & Artifacts Saved.")
    return {
        "train_rows": len(y_train_5class),
        "test_rows": len(y_test_5class),
        "feature_count": len(preprocessor.feature_names),
        "classes_5class": list(preprocessor.label_encoder_5class.classes_)
    }


def process_cicids2017():
    log("=" * 60)
    log("EXECUTING CICIDS2017 PREPROCESSING PIPELINE")
    log("=" * 60)

    log("Reading raw 8 CICIDS2017 CSV files with float32 downcasting...")
    dfs = []
    for filename in CICIDS2017_FILES:
        filepath = os.path.join(RAW_DATA_DIR, filename)
        if not os.path.exists(filepath):
            continue
        df = pd.read_csv(filepath, low_memory=False)
        df.columns = df.columns.str.strip()
        num_cols = df.select_dtypes(include=[np.number]).columns
        # Explicitly downcast numeric columns to float32 to conserve 50% RAM
        df[num_cols] = df[num_cols].astype(np.float32)
        dfs.append(df)

    log("Combining CSV files memory-consciously...")
    full_df = pd.concat(dfs, ignore_index=True)
    del dfs

    label_col = 'Label' if 'Label' in full_df.columns else [c for c in full_df.columns if 'label' in c.lower()][0]
    
    full_df[label_col] = full_df[label_col].astype(str).str.strip()

    X = full_df.drop(columns=[label_col])
    y = full_df[label_col]
    del full_df

    log(f"Raw CICIDS2017 Combined: {X.shape[0]} rows x {X.shape[1]} columns")

    log("Performing Stratified 80/20 Train/Test Split (random_state=42)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    del X, y

    log("Fitting CICIDS2017 preprocessor STRICTLY on X_train...")
    preprocessor = CICIDS2017Preprocessor()
    X_train_trans, y_train_encoded, X_train_clean = preprocessor.fit_transform_train(X_train, y_train)

    log("Transforming X_test using pre-fitted preprocessor...")
    X_test_trans, y_test_encoded, X_test_clean = preprocessor.transform_test(X_test, y_test)

    log(f"CICIDS2017 Transformed Shapes:")
    log(f"  - Train X: {X_train_trans.shape}, y: {y_train_encoded.shape}")
    log(f"  - Test X: {X_test_trans.shape}, y: {y_test_encoded.shape}")
    log(f"  - Transformed Feature Count: {len(preprocessor.feature_names)}")

    # Save artifacts
    cic_dir = os.path.join(PROCESSED_DATA_DIR, "cicids2017")
    os.makedirs(cic_dir, exist_ok=True)

    joblib.dump(preprocessor.column_transformer, os.path.join(ARTIFACTS_DIR, "preprocessors", "cicids2017_preprocessor.joblib"))
    joblib.dump(preprocessor.label_encoder, os.path.join(ARTIFACTS_DIR, "encoders", "cicids2017_label_encoder.joblib"))

    with open(os.path.join(ARTIFACTS_DIR, "features", "cicids2017_features.json"), "w") as f:
        json.dump(preprocessor.feature_names, f, indent=2)

    log("Exporting compressed processed datasets to data/processed/cicids2017/...")
    np.savez_compressed(
        os.path.join(cic_dir, "train_processed.npz"),
        X=X_train_trans,
        y=y_train_encoded
    )

    np.savez_compressed(
        os.path.join(cic_dir, "test_processed.npz"),
        X=X_test_trans,
        y=y_test_encoded
    )

    log("CICIDS2017 Preprocessing Complete & Artifacts Saved.")
    return {
        "train_rows": len(y_train_encoded),
        "test_rows": len(y_test_encoded),
        "feature_count": len(preprocessor.feature_names),
        "classes": list(preprocessor.label_encoder.classes_)
    }


def main():
    nsl_res = process_nsl_kdd()
    cic_res = process_cicids2017()

    meta = {
        "nsl_kdd": nsl_res,
        "cicids2017": cic_res,
        "leakage_prevention": "Strictly enforced fit on X_train only",
        "random_state": 42
    }

    os.makedirs(os.path.join(ARTIFACTS_DIR, "metadata"), exist_ok=True)
    with open(os.path.join(ARTIFACTS_DIR, "metadata", "preprocessing_metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)

    log("=" * 60)
    log("ALL PREPROCESSING PIPELINES EXECUTED SUCCESSFULLY.")
    log("=" * 60)


if __name__ == "__main__":
    main()
