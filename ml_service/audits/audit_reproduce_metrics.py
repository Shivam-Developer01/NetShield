import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

import json
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    classification_report
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ARTIFACTS_DIR = os.path.join(PROJECT_ROOT, "artifacts")
PROCESSED_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "processed")
sys.path.append(os.path.join(PROJECT_ROOT, "ml_service", "src", "features"))

def evaluate_saved_model(dataset_name):
    print(f"============================================================")
    print(f"REPRODUCING EVALUATION: {dataset_name.upper()}")
    print(f"============================================================")
    
    prod_dir = os.path.join(ARTIFACTS_DIR, "production", dataset_name)
    model = joblib.load(os.path.join(prod_dir, "best_model.joblib"))
    selector = joblib.load(os.path.join(prod_dir, "feature_selector.joblib"))
    encoder = joblib.load(os.path.join(prod_dir, "label_encoder.joblib"))
    
    with open(os.path.join(prod_dir, "feature_schema.json"), "r") as f:
        schema = json.load(f)
        
    with open(os.path.join(prod_dir, "metadata.json"), "r") as f:
        meta = json.load(f)
        
    print(f"Model class: {type(model).__name__}")
    print(f"Model parameters: {model.get_params() if hasattr(model, 'get_params') else 'N/A'}")
    print(f"Metadata model version: {meta.get('model_version')}")
    print(f"Reported accuracy in metadata: {meta.get('evaluation_metrics', {}).get('accuracy')}")
    print(f"Reported weighted F1 in metadata: {meta.get('evaluation_metrics', {}).get('f1_weighted')}")
    print(f"Selected feature count: {len(schema)}")
    print(f"Encoder classes: {list(encoder.classes_)}")
    
    # Load reduced test data
    test_reduced_path = os.path.join(PROCESSED_DATA_DIR, dataset_name, "test_reduced.npz")
    test_data = np.load(test_reduced_path)
    X_test_reduced = test_data['X']
    
    if dataset_name == "nsl_kdd":
        y_test = test_data['y_5class']
    else:
        y_test = test_data['y']
        
    print(f"X_test_reduced shape: {X_test_reduced.shape}")
    print(f"y_test shape: {y_test.shape}")
    print(f"Unique values in y_test: {np.unique(y_test, return_counts=True)}")
    
    # Predict
    y_pred = model.predict(X_test_reduced)
    
    # Metrics
    acc = accuracy_score(y_test, y_pred)
    p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(y_test, y_pred, average='macro', zero_division=0)
    p_weighted, r_weighted, f1_weighted, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted', zero_division=0)
    
    cm = confusion_matrix(y_test, y_pred)
    correct_count = int(np.sum(y_test == y_pred))
    incorrect_count = int(len(y_test) - correct_count)
    
    print(f"\n--- INDEPENDENT REPRODUCTION RESULTS ---")
    print(f"Total Test Samples: {len(y_test)}")
    print(f"Correctly Classified: {correct_count} ({acc*100:.4f}%)")
    print(f"Incorrectly Classified: {incorrect_count} ({(1-acc)*100:.4f}%)")
    print(f"Accuracy: {acc:.6f} ({acc*100:.4f}%)")
    print(f"Macro Precision: {p_macro:.6f}")
    print(f"Macro Recall: {r_macro:.6f}")
    print(f"Macro F1: {f1_macro:.6f}")
    print(f"Weighted Precision: {p_weighted:.6f}")
    print(f"Weighted Recall: {r_weighted:.6f}")
    print(f"Weighted F1: {f1_weighted:.6f}")
    
    # Class names
    unique_y = np.unique(np.concatenate([y_test, y_pred]))
    target_names = [encoder.classes_[i] if i < len(encoder.classes_) else f"Unknown_{i}" for i in unique_y]
    
    print(f"\nConfusion Matrix (shape {cm.shape}):")
    print(cm)
    
    print(f"\nPer-class Classification Report:")
    report_dict = classification_report(y_test, y_pred, target_names=target_names, output_dict=True, zero_division=0)
    print(classification_report(y_test, y_pred, target_names=target_names, zero_division=0))
    
    # Baseline comparison: Majority class
    vals, counts = np.unique(y_test, return_counts=True)
    maj_idx = np.argmax(counts)
    maj_acc = counts[maj_idx] / len(y_test)
    print(f"\nBaseline: Majority Class ({target_names[maj_idx]}) Accuracy: {maj_acc:.4f} ({maj_acc*100:.2f}%)")
    
    # Binary Attack vs Benign analysis
    if dataset_name == "cicids2017":
        # Find index for 'BENIGN'
        benign_idx = list(encoder.classes_).index('BENIGN')
        benign_test = (y_test == benign_idx)
        attack_test = ~benign_test
        benign_pred = (y_pred == benign_idx)
        attack_pred = ~benign_pred
        
        # Malicious samples classified as benign (False Negatives)
        fn_malicious = np.sum(attack_test & benign_pred)
        # Benign samples classified as malicious (False Positives)
        fp_benign = np.sum(benign_test & attack_pred)
        # True Positives for attacks
        tp_malicious = np.sum(attack_test & attack_pred)
        # True Negatives for attacks (correct benign)
        tn_benign = np.sum(benign_test & benign_pred)
        
        attack_recall = tp_malicious / np.sum(attack_test)
        benign_recall = tn_benign / np.sum(benign_test)
        malicious_precision = tp_malicious / np.sum(attack_pred) if np.sum(attack_pred) > 0 else 0
        fnr = fn_malicious / np.sum(attack_test)
        fpr = fp_benign / np.sum(benign_test)
        
        print(f"\n--- CYBERSECURITY BINARY AGGREGATION (CICIDS2017) ---")
        print(f"Total Benign Samples: {np.sum(benign_test)}")
        print(f"Total Attack Samples: {np.sum(attack_test)}")
        print(f"True Positives (Attacks caught): {tp_malicious}")
        print(f"False Negatives (Attacks missed as BENIGN): {fn_malicious} (FNR: {fnr*100:.4f}%)")
        print(f"False Positives (Benign flagged as Attack): {fp_benign} (FPR: {fpr*100:.4f}%)")
        print(f"Attack Recall: {attack_recall:.6f} ({attack_recall*100:.4f}%)")
        print(f"Benign Recall: {benign_recall:.6f} ({benign_recall*100:.4f}%)")
        print(f"Malicious Traffic Precision: {malicious_precision:.6f} ({malicious_precision*100:.4f}%)")
        
    elif dataset_name == "nsl_kdd":
        # In NSL-KDD 5-class, Normal is benign
        normal_idx = list(encoder.classes_).index('Normal')
        benign_test = (y_test == normal_idx)
        attack_test = ~benign_test
        benign_pred = (y_pred == normal_idx)
        attack_pred = ~benign_pred
        
        fn_malicious = np.sum(attack_test & benign_pred)
        fp_benign = np.sum(benign_test & attack_pred)
        tp_malicious = np.sum(attack_test & attack_pred)
        tn_benign = np.sum(benign_test & benign_pred)
        
        attack_recall = tp_malicious / np.sum(attack_test)
        benign_recall = tn_benign / np.sum(benign_test)
        malicious_precision = tp_malicious / np.sum(attack_pred) if np.sum(attack_pred) > 0 else 0
        fnr = fn_malicious / np.sum(attack_test)
        fpr = fp_benign / np.sum(benign_test)
        
        print(f"\n--- CYBERSECURITY BINARY AGGREGATION (NSL-KDD) ---")
        print(f"Total Normal (Benign) Samples: {np.sum(benign_test)}")
        print(f"Total Attack Samples: {np.sum(attack_test)}")
        print(f"True Positives (Attacks caught): {tp_malicious}")
        print(f"False Negatives (Attacks missed as Normal): {fn_malicious} (FNR: {fnr*100:.4f}%)")
        print(f"False Positives (Normal flagged as Attack): {fp_benign} (FPR: {fpr*100:.4f}%)")
        print(f"Attack Recall: {attack_recall:.6f} ({attack_recall*100:.4f}%)")
        print(f"Benign Recall: {benign_recall:.6f} ({benign_recall*100:.4f}%)")
        print(f"Malicious Traffic Precision: {malicious_precision:.6f} ({malicious_precision*100:.4f}%)")

    return {
        "accuracy": float(acc),
        "macro_precision": float(p_macro),
        "macro_recall": float(r_macro),
        "macro_f1": float(f1_macro),
        "weighted_precision": float(p_weighted),
        "weighted_recall": float(r_weighted),
        "weighted_f1": float(f1_weighted),
        "total_test": len(y_test),
        "correct": correct_count,
        "incorrect": incorrect_count,
        "report": report_dict
    }

if __name__ == "__main__":
    nsl_res = evaluate_saved_model("nsl_kdd")
    cic_res = evaluate_saved_model("cicids2017")
    
    os.makedirs(os.path.join(PROJECT_ROOT, "scratch", "audit"), exist_ok=True)
    with open(os.path.join(PROJECT_ROOT, "scratch", "audit", "reproduction_summary.json"), "w") as f:
        json.dump({"nsl_kdd": nsl_res, "cicids2017": cic_res}, f, indent=2)
