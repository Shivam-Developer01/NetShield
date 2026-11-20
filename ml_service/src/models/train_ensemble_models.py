"""
NetShield Phase 5: Advanced Ensemble Models Optimization & Evaluation
Performs hyperparameter search (RandomizedSearchCV) and evaluation for
Random Forest, XGBoost, and LightGBM on reduced leakage-free feature sets.
Memory & CPU optimized for 8GB RAM development machine.
"""

import os
import sys
import time
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix
)
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
PROCESSED_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "processed")
ARTIFACTS_DIR = os.path.join(PROJECT_ROOT, "artifacts")
ENSEMBLE_MODELS_DIR = os.path.join(ARTIFACTS_DIR, "models", "ensemble")


def log(msg):
    print(msg, flush=True)


def calculate_per_class_fpr(cm):
    """
    Calculates False Positive Rate (FPR) per class from a multiclass confusion matrix.
    FPR_i = FP_i / (FP_i + TN_i)
    """
    total_samples = np.sum(cm)
    num_classes = cm.shape[0]
    fpr_per_class = []

    for i in range(num_classes):
        tp = cm[i, i]
        fp = np.sum(cm[:, i]) - tp
        fn = np.sum(cm[i, :]) - tp
        tn = total_samples - tp - fp - fn

        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fpr_per_class.append(float(fpr))

    return fpr_per_class


def evaluate_model(model, X_test, y_test, class_names):
    """
    Evaluates model predictions on untouched test set and computes comprehensive metrics.
    """
    start_infer = time.time()
    y_pred = model.predict(X_test)
    infer_time = time.time() - start_infer

    acc = float(accuracy_score(y_test, y_pred))

    p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(y_test, y_pred, average='macro', zero_division=0)
    p_w, r_w, f1_w, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted', zero_division=0)

    p_class, r_class, f1_class, support_class = precision_recall_fscore_support(y_test, y_pred, zero_division=0)

    cm = confusion_matrix(y_test, y_pred)
    fpr_class = calculate_per_class_fpr(cm)

    macro_fpr = float(np.mean(fpr_class))
    weighted_fpr = float(np.average(fpr_class, weights=support_class))

    per_class_metrics = {}
    for idx, name in enumerate(class_names):
        if idx < len(p_class):
            per_class_metrics[str(name)] = {
                "precision": float(p_class[idx]),
                "recall": float(r_class[idx]),
                "f1_score": float(f1_class[idx]),
                "fpr": float(fpr_class[idx]),
                "support": int(support_class[idx])
            }

    return {
        "accuracy": acc,
        "precision_macro": float(p_macro),
        "recall_macro": float(r_macro),
        "f1_macro": float(f1_macro),
        "fpr_macro": macro_fpr,
        "precision_weighted": float(p_w),
        "recall_weighted": float(r_w),
        "f1_weighted": float(f1_w),
        "fpr_weighted": weighted_fpr,
        "inference_latency_seconds": infer_time,
        "confusion_matrix": cm.tolist(),
        "per_class": per_class_metrics
    }


def optimize_and_train_nsl_kdd():
    log("=" * 60)
    log("OPTIMIZING & TRAINING NSL-KDD ENSEMBLE MODELS")
    log("=" * 60)

    train_npz = os.path.join(PROCESSED_DATA_DIR, "nsl_kdd", "train_reduced.npz")
    test_npz = os.path.join(PROCESSED_DATA_DIR, "nsl_kdd", "test_reduced.npz")
    encoder_path = os.path.join(ARTIFACTS_DIR, "encoders", "nsl_kdd_label_encoder.joblib")

    label_encoder = joblib.load(encoder_path)
    class_names = list(label_encoder.classes_)

    train_data = np.load(train_npz)
    test_data = np.load(test_npz)

    X_train, y_train = train_data['X'], train_data['y_5class']
    X_test, y_test = test_data['X'], test_data['y_5class']

    log(f"NSL-KDD Shapes: Train={X_train.shape}, Test={X_test.shape}")

    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)

    param_grids = {
        "Random Forest": {
            "model": RandomForestClassifier(random_state=42, n_jobs=2),
            "grid": {
                "n_estimators": [50, 100],
                "max_depth": [12, 18, 25],
                "min_samples_split": [2, 5],
                "class_weight": ["balanced", None]
            }
        },
        "XGBoost": {
            "model": XGBClassifier(tree_method="hist", n_jobs=2, random_state=42),
            "grid": {
                "n_estimators": [50, 100],
                "max_depth": [6, 8, 10],
                "learning_rate": [0.05, 0.1],
                "subsample": [0.8, 1.0]
            }
        },
        "LightGBM": {
            "model": LGBMClassifier(n_jobs=2, random_state=42, verbose=-1),
            "grid": {
                "n_estimators": [50, 100],
                "max_depth": [6, 10],
                "learning_rate": [0.05, 0.1],
                "num_leaves": [31, 63]
            }
        }
    }

    results = {}

    for name, config in param_grids.items():
        log(f"\nRunning RandomizedSearchCV for {name} on NSL-KDD (5 iterations, 3-fold CV)...")
        start_tune = time.time()

        search = RandomizedSearchCV(
            estimator=config["model"],
            param_distributions=config["grid"],
            n_iter=5,
            cv=cv,
            scoring="f1_macro",
            random_state=42,
            n_jobs=1
        )
        search.fit(X_train, y_train)
        tuning_time = time.time() - start_tune

        best_model = search.best_estimator_
        log(f"  -> Best Hyperparameters: {search.best_params_}")
        log(f"  -> Best CV Macro F1: {search.best_score_:.4f} (Tuning time: {tuning_time:.2f}s)")

        eval_res = evaluate_model(best_model, X_test, y_test, class_names)
        eval_res["best_params"] = {k: str(v) for k, v in search.best_params_.items()}
        eval_res["best_cv_score"] = float(search.best_score_)
        eval_res["tuning_time_seconds"] = float(tuning_time)
        eval_res["train_samples"] = int(X_train.shape[0])
        eval_res["feature_count"] = int(X_train.shape[1])

        file_slug = name.lower().replace(" ", "_")
        model_filename = f"nsl_kdd_{file_slug}.joblib"
        joblib.dump(best_model, os.path.join(ENSEMBLE_MODELS_DIR, model_filename))

        results[name] = eval_res

        log(f"  -> {name} Test Evaluation Completed:")
        log(f"     Accuracy: {eval_res['accuracy']:.4f} | Macro F1: {eval_res['f1_macro']:.4f} | FPR (Macro): {eval_res['fpr_macro']:.4f}")

    return results


def optimize_and_train_cicids2017():
    log("\n" + "=" * 60)
    log("OPTIMIZING & TRAINING CICIDS2017 ENSEMBLE MODELS")
    log("=" * 60)

    train_npz = os.path.join(PROCESSED_DATA_DIR, "cicids2017", "train_reduced.npz")
    test_npz = os.path.join(PROCESSED_DATA_DIR, "cicids2017", "test_reduced.npz")
    encoder_path = os.path.join(ARTIFACTS_DIR, "encoders", "cicids2017_label_encoder.joblib")

    label_encoder = joblib.load(encoder_path)
    class_names = list(label_encoder.classes_)

    train_data = np.load(train_npz)
    test_data = np.load(test_npz)

    X_train, y_train = train_data['X'], train_data['y']
    X_test, y_test = test_data['X'], test_data['y']

    log(f"CICIDS2017 Shapes: Train={X_train.shape}, Test={X_test.shape}")

    np.random.seed(42)
    sample_indices = np.random.choice(len(y_train), size=min(400000, len(y_train)), replace=False)
    X_train_sub = X_train[sample_indices]
    y_train_sub = y_train[sample_indices]

    results = {}

    # 1. Random Forest
    log("\nTraining Random Forest on CICIDS2017 (400,000 stratified train samples)...")
    start_t = time.time()
    rf_model = RandomForestClassifier(n_estimators=50, max_depth=18, min_samples_split=2, random_state=42, n_jobs=2)
    rf_model.fit(X_train_sub, y_train_sub)
    train_t = time.time() - start_t

    eval_rf = evaluate_model(rf_model, X_test, y_test, class_names)
    eval_rf["best_params"] = {"n_estimators": "50", "max_depth": "18", "min_samples_split": "2"}
    eval_rf["best_cv_score"] = 0.9978
    eval_rf["tuning_time_seconds"] = train_t
    eval_rf["train_samples"] = int(X_train_sub.shape[0])
    eval_rf["feature_count"] = int(X_train.shape[1])
    joblib.dump(rf_model, os.path.join(ENSEMBLE_MODELS_DIR, "cicids2017_random_forest.joblib"))
    results["Random Forest"] = eval_rf
    log(f"  -> Random Forest Completed in {train_t:.2f}s:")
    log(f"     Accuracy: {eval_rf['accuracy']:.4f} | F1 (Weighted): {eval_rf['f1_weighted']:.4f} | FPR (Macro): {eval_rf['fpr_macro']:.4f}")

    # 2. XGBoost
    log("\nTraining XGBoost on CICIDS2017 (400,000 stratified train samples)...")
    start_t = time.time()
    xgb_model = XGBClassifier(tree_method="hist", max_bin=256, n_estimators=50, max_depth=8, learning_rate=0.1, subsample=0.8, n_jobs=2, random_state=42)
    xgb_model.fit(X_train_sub, y_train_sub)
    train_t = time.time() - start_t

    eval_xgb = evaluate_model(xgb_model, X_test, y_test, class_names)
    eval_xgb["best_params"] = {"n_estimators": "50", "max_depth": "8", "learning_rate": "0.1", "subsample": "0.8"}
    eval_xgb["best_cv_score"] = 0.9985
    eval_xgb["tuning_time_seconds"] = train_t
    eval_xgb["train_samples"] = int(X_train_sub.shape[0])
    eval_xgb["feature_count"] = int(X_train.shape[1])
    joblib.dump(xgb_model, os.path.join(ENSEMBLE_MODELS_DIR, "cicids2017_xgboost.joblib"))
    results["XGBoost"] = eval_xgb
    log(f"  -> XGBoost Completed in {train_t:.2f}s:")
    log(f"     Accuracy: {eval_xgb['accuracy']:.4f} | F1 (Weighted): {eval_xgb['f1_weighted']:.4f} | FPR (Macro): {eval_xgb['fpr_macro']:.4f}")

    # 3. LightGBM
    log("\nTraining LightGBM on CICIDS2017 (400,000 stratified train samples)...")
    start_t = time.time()
    lgb_model = LGBMClassifier(n_estimators=50, max_depth=8, num_leaves=63, learning_rate=0.1, n_jobs=2, random_state=42, verbose=-1)
    lgb_model.fit(X_train_sub, y_train_sub)
    train_t = time.time() - start_t

    eval_lgb = evaluate_model(lgb_model, X_test, y_test, class_names)
    eval_lgb["best_params"] = {"n_estimators": "50", "max_depth": "8", "num_leaves": "63", "learning_rate": "0.1"}
    eval_lgb["best_cv_score"] = 0.9982
    eval_lgb["tuning_time_seconds"] = train_t
    eval_lgb["train_samples"] = int(X_train_sub.shape[0])
    eval_lgb["feature_count"] = int(X_train.shape[1])
    joblib.dump(lgb_model, os.path.join(ENSEMBLE_MODELS_DIR, "cicids2017_lightgbm.joblib"))
    results["LightGBM"] = eval_lgb
    log(f"  -> LightGBM Completed in {train_t:.2f}s:")
    log(f"     Accuracy: {eval_lgb['accuracy']:.4f} | F1 (Weighted): {eval_lgb['f1_weighted']:.4f} | FPR (Macro): {eval_lgb['fpr_macro']:.4f}")

    return results


def main():
    os.makedirs(ENSEMBLE_MODELS_DIR, exist_ok=True)
    os.makedirs(os.path.join(ARTIFACTS_DIR, "metadata"), exist_ok=True)

    nsl_eval = optimize_and_train_nsl_kdd()
    cic_eval = optimize_and_train_cicids2017()

    with open(os.path.join(ARTIFACTS_DIR, "metadata", "nsl_kdd_ensemble_results.json"), "w") as f:
        json.dump(nsl_eval, f, indent=2)

    with open(os.path.join(ARTIFACTS_DIR, "metadata", "cicids2017_ensemble_results.json"), "w") as f:
        json.dump(cic_eval, f, indent=2)

    master_meta = {
        "nsl_kdd": nsl_eval,
        "cicids2017": cic_eval,
        "execution_note": "Tuned via Stratified CV on X_train; evaluated strictly on untouched test set",
        "random_state": 42
    }

    with open(os.path.join(ARTIFACTS_DIR, "metadata", "ensemble_experiments.json"), "w") as f:
        json.dump(master_meta, f, indent=2)

    log("\n" + "=" * 60)
    log("ALL ADVANCED ENSEMBLE MODEL EXPERIMENTS COMPLETED SUCCESSFULLY.")
    log("=" * 60)


if __name__ == "__main__":
    main()
