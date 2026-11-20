"""
NetShield Phase 4: Baseline Machine Learning Models Training & Evaluation
Trains and evaluates Logistic Regression (SGD/LBFGS), Decision Tree, and Gaussian Naive Bayes
on reduced leakage-free feature sets for NSL-KDD and CICIDS2017 independently.
Memory & CPU optimized for 8GB RAM development machine.
"""

import os
import sys
import time
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix
)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
PROCESSED_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "processed")
ARTIFACTS_DIR = os.path.join(PROJECT_ROOT, "artifacts")
BASELINE_MODELS_DIR = os.path.join(ARTIFACTS_DIR, "models", "baseline")


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


def train_nsl_kdd_baselines():
    log("=" * 60)
    log("TRAINING NSL-KDD BASELINE MODELS")
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

    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000, class_weight='balanced', random_state=42),
        "Decision Tree": DecisionTreeClassifier(max_depth=15, random_state=42),
        "Gaussian Naive Bayes": GaussianNB()
    }

    results = {}

    for model_name, model in models.items():
        log(f"\nTraining {model_name} on NSL-KDD...")
        start_t = time.time()
        model.fit(X_train, y_train)
        train_time = time.time() - start_t

        eval_res = evaluate_model(model, X_test, y_test, class_names)
        eval_res["train_time_seconds"] = train_time
        eval_res["train_samples"] = int(X_train.shape[0])
        eval_res["feature_count"] = int(X_train.shape[1])

        file_slug = model_name.lower().replace(" ", "_")
        model_filename = f"nsl_kdd_{file_slug}.joblib"
        joblib.dump(model, os.path.join(BASELINE_MODELS_DIR, model_filename))

        results[model_name] = eval_res

        log(f"  -> {model_name} Completed in {train_time:.2f}s:")
        log(f"     Accuracy: {eval_res['accuracy']:.4f} | F1 (Weighted): {eval_res['f1_weighted']:.4f} | FPR (Macro): {eval_res['fpr_macro']:.4f}")

    return results


def train_cicids2017_baselines():
    log("\n" + "=" * 60)
    log("TRAINING CICIDS2017 BASELINE MODELS")
    log("=" * 60)

    train_npz = os.path.join(PROCESSED_DATA_DIR, "cicids2017", "train_reduced.npz")
    test_npz = os.path.join(PROCESSED_DATA_DIR, "cicids2017", "test_reduced.npz")
    encoder_path = os.path.join(ARTIFACTS_DIR, "encoders", "cicids2017_label_encoder.joblib")

    label_encoder = joblib.load(encoder_path)
    class_names = list(label_encoder.classes_)

    log("Loading CICIDS2017 reduced train and test sets...")
    train_data = np.load(train_npz)
    test_data = np.load(test_npz)

    X_train, y_train = train_data['X'], train_data['y']
    X_test, y_test = test_data['X'], test_data['y']

    log(f"CICIDS2017 Shapes: Train={X_train.shape}, Test={X_test.shape}")

    # Use fast SGDClassifier for Logistic Regression on 2.26M samples (sample for fast convergence)
    np.random.seed(42)
    sample_indices = np.random.choice(len(y_train), size=min(250000, len(y_train)), replace=False)
    X_train_lr_sample = X_train[sample_indices]
    y_train_lr_sample = y_train[sample_indices]

    models_config = [
        ("Logistic Regression", SGDClassifier(loss='log_loss', max_iter=50, random_state=42), X_train_lr_sample, y_train_lr_sample),
        ("Decision Tree", DecisionTreeClassifier(max_depth=15, random_state=42), X_train, y_train),
        ("Gaussian Naive Bayes", GaussianNB(), X_train, y_train)
    ]

    results = {}

    for model_name, model, X_tr, y_tr in models_config:
        log(f"\nTraining {model_name} on CICIDS2017 ({X_tr.shape[0]} train samples)...")
        start_t = time.time()
        model.fit(X_tr, y_tr)
        train_time = time.time() - start_t

        eval_res = evaluate_model(model, X_test, y_test, class_names)
        eval_res["train_time_seconds"] = train_time
        eval_res["train_samples"] = int(X_tr.shape[0])
        eval_res["feature_count"] = int(X_tr.shape[1])

        file_slug = model_name.lower().replace(" ", "_")
        model_filename = f"cicids2017_{file_slug}.joblib"
        joblib.dump(model, os.path.join(BASELINE_MODELS_DIR, model_filename))

        results[model_name] = eval_res

        log(f"  -> {model_name} Completed in {train_time:.2f}s:")
        log(f"     Accuracy: {eval_res['accuracy']:.4f} | F1 (Weighted): {eval_res['f1_weighted']:.4f} | FPR (Macro): {eval_res['fpr_macro']:.4f}")

    return results


def main():
    os.makedirs(BASELINE_MODELS_DIR, exist_ok=True)
    os.makedirs(os.path.join(ARTIFACTS_DIR, "metadata"), exist_ok=True)

    nsl_eval = train_nsl_kdd_baselines()
    cic_eval = train_cicids2017_baselines()

    with open(os.path.join(ARTIFACTS_DIR, "metadata", "nsl_kdd_baseline_eval.json"), "w") as f:
        json.dump(nsl_eval, f, indent=2)

    with open(os.path.join(ARTIFACTS_DIR, "metadata", "cicids2017_baseline_eval.json"), "w") as f:
        json.dump(cic_eval, f, indent=2)

    master_meta = {
        "nsl_kdd": nsl_eval,
        "cicids2017": cic_eval,
        "execution_note": "Evaluated strictly on untouched test sets",
        "random_state": 42
    }

    with open(os.path.join(ARTIFACTS_DIR, "metadata", "baseline_models_metadata.json"), "w") as f:
        json.dump(master_meta, f, indent=2)

    log("\n" + "=" * 60)
    log("ALL BASELINE MODEL EXPERIMENTS COMPLETED SUCCESSFULLY.")
    log("=" * 60)


if __name__ == "__main__":
    main()
