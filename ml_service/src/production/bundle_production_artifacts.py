"""
NetShield Phase 6: Production Artifact Bundler
Bundles verified preprocessors, feature selectors, best models, label encoders,
feature schemas, and comprehensive metadata into artifacts/production/ for deployment.
"""

import os
import sys
import json
import shutil
import joblib

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
ARTIFACTS_DIR = os.path.join(PROJECT_ROOT, "artifacts")
PRODUCTION_DIR = os.path.join(ARTIFACTS_DIR, "production")


def log(msg):
    print(msg, flush=True)


def bundle_nsl_kdd_artifacts():
    log("Bundling NSL-KDD Production Artifacts...")
    prod_nsl_dir = os.path.join(PRODUCTION_DIR, "nsl_kdd")
    os.makedirs(prod_nsl_dir, exist_ok=True)

    # File mappings
    src_dst_files = [
        (os.path.join(ARTIFACTS_DIR, "models", "ensemble", "nsl_kdd_xgboost.joblib"), os.path.join(prod_nsl_dir, "best_model.joblib")),
        (os.path.join(ARTIFACTS_DIR, "preprocessors", "nsl_kdd_preprocessor.joblib"), os.path.join(prod_nsl_dir, "preprocessor.joblib")),
        (os.path.join(ARTIFACTS_DIR, "features", "nsl_kdd_feature_selector.joblib"), os.path.join(prod_nsl_dir, "feature_selector.joblib")),
        (os.path.join(ARTIFACTS_DIR, "encoders", "nsl_kdd_label_encoder.joblib"), os.path.join(prod_nsl_dir, "label_encoder.joblib")),
        (os.path.join(ARTIFACTS_DIR, "features", "nsl_kdd_selected_features.json"), os.path.join(prod_nsl_dir, "feature_schema.json"))
    ]

    for src, dst in src_dst_files:
        assert os.path.exists(src), f"Source artifact missing: {src}"
        shutil.copy2(src, dst)
        log(f"  -> Copied {os.path.basename(src)} -> {os.path.basename(dst)}")

    # Load Phase 5 results for metadata
    with open(os.path.join(ARTIFACTS_DIR, "metadata", "nsl_kdd_ensemble_results.json"), "r") as f:
        ensemble_meta = json.load(f)

    xgb_results = ensemble_meta["XGBoost"]

    metadata = {
        "model_version": "NetShield-NSLKDD-XGBoost-v1.0",
        "dataset": "NSL-KDD",
        "algorithm": "XGBoost Classifier (Histogram Gradient Boosting)",
        "training_samples": 125973,
        "test_samples": 22544,
        "feature_count": 37,
        "selected_features_file": "feature_schema.json",
        "hyperparameters": xgb_results["best_params"],
        "evaluation_metrics": {
            "accuracy": xgb_results["accuracy"],
            "precision_macro": xgb_results["precision_macro"],
            "recall_macro": xgb_results["recall_macro"],
            "f1_macro": xgb_results["f1_macro"],
            "f1_weighted": xgb_results["f1_weighted"],
            "fpr_macro": xgb_results["fpr_macro"],
            "inference_latency_seconds": xgb_results["inference_latency_seconds"]
        },
        "per_class_metrics": xgb_results["per_class"],
        "random_seed": 42,
        "known_limitations": [
            "Evaluated on canonical KDDTest+ split which contains 17 unseen attack variations.",
            "Higher FPR on rare R2L/U2R attack categories due to extreme training class imbalance."
        ]
    }

    with open(os.path.join(prod_nsl_dir, "metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    log("  -> Saved NSL-KDD production metadata.json")


def bundle_cicids2017_artifacts():
    log("\nBundling CICIDS2017 Production Artifacts...")
    prod_cic_dir = os.path.join(PRODUCTION_DIR, "cicids2017")
    os.makedirs(prod_cic_dir, exist_ok=True)

    src_dst_files = [
        (os.path.join(ARTIFACTS_DIR, "models", "ensemble", "cicids2017_xgboost.joblib"), os.path.join(prod_cic_dir, "best_model.joblib")),
        (os.path.join(ARTIFACTS_DIR, "preprocessors", "cicids2017_preprocessor.joblib"), os.path.join(prod_cic_dir, "preprocessor.joblib")),
        (os.path.join(ARTIFACTS_DIR, "features", "cicids2017_feature_selector.joblib"), os.path.join(prod_cic_dir, "feature_selector.joblib")),
        (os.path.join(ARTIFACTS_DIR, "encoders", "cicids2017_label_encoder.joblib"), os.path.join(prod_cic_dir, "label_encoder.joblib")),
        (os.path.join(ARTIFACTS_DIR, "features", "cicids2017_selected_features.json"), os.path.join(prod_cic_dir, "feature_schema.json"))
    ]

    for src, dst in src_dst_files:
        assert os.path.exists(src), f"Source artifact missing: {src}"
        shutil.copy2(src, dst)
        log(f"  -> Copied {os.path.basename(src)} -> {os.path.basename(dst)}")

    # Load Phase 5 results for metadata
    with open(os.path.join(ARTIFACTS_DIR, "metadata", "cicids2017_ensemble_results.json"), "r") as f:
        ensemble_meta = json.load(f)

    xgb_results = ensemble_meta["XGBoost"]

    metadata = {
        "model_version": "NetShield-CICIDS2017-XGBoost-v1.0",
        "dataset": "CICIDS2017",
        "algorithm": "XGBoost Classifier (Histogram Gradient Boosting)",
        "training_samples": 400000,
        "test_samples": 566149,
        "feature_count": 43,
        "selected_features_file": "feature_schema.json",
        "hyperparameters": xgb_results["best_params"],
        "evaluation_metrics": {
            "accuracy": xgb_results["accuracy"],
            "precision_macro": xgb_results["precision_macro"],
            "recall_macro": xgb_results["recall_macro"],
            "f1_macro": xgb_results["f1_macro"],
            "f1_weighted": xgb_results["f1_weighted"],
            "fpr_macro": xgb_results["fpr_macro"],
            "inference_latency_seconds": xgb_results["inference_latency_seconds"]
        },
        "per_class_metrics": xgb_results["per_class"],
        "random_seed": 42,
        "known_limitations": [
            "Requires modern 78-column flow header schema input before feature transformation.",
            "Trained on 400,000 stratified training samples for memory-conscious CPU execution."
        ]
    }

    with open(os.path.join(prod_cic_dir, "metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    log("  -> Saved CICIDS2017 production metadata.json")


def main():
    bundle_nsl_kdd_artifacts()
    bundle_cicids2017_artifacts()
    log("\n============================================================")
    log("PRODUCTION ARTIFACT BUNDLE CREATED SUCCESSFULLY IN artifacts/production/")
    log("============================================================")


if __name__ == "__main__":
    main()
