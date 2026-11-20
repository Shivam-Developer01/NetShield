"""
Phase 19.7 - Step 1: NSL-KDD Comprehensive Data Audit & v1.2 Error Analysis
=============================================================================
Audits:
1. KDDTrain+ vs KDDTest+ sample counts, distributions, duplicate rows.
2. Attack types and families present in Train vs Test (novel variants).
3. Feature distributions, cardinality, constant columns, correlations.
4. Class-by-class and family-by-family failure profiling of v1.2.
"""

import os
import sys
import json
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import confusion_matrix

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
RAW_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "raw")
V12_DIR = os.path.join(PROJECT_ROOT, "artifacts", "v1.2", "nsl_kdd")
OUT_DIR = os.path.join(os.path.dirname(__file__), "results")
os.makedirs(OUT_DIR, exist_ok=True)

sys.path.append(os.path.join(PROJECT_ROOT, "ml_service", "src", "preprocessing"))
sys.path.append(os.path.join(PROJECT_ROOT, "ml_service", "src", "features"))
from nsl_kdd_preprocessor import NSL_KDD_COLUMNS, NSL_KDD_5CLASS_MAP
from feature_selector import NetShieldFeatureSelector

def run_audit():
    print("=" * 70)
    print("PHASE 19.7 - STEP 1: NSL-KDD DATA AUDIT & ERROR PROFILING")
    print("=" * 70)
    
    train_path = os.path.join(RAW_DATA_DIR, "KDDTrain+.txt")
    test_path = os.path.join(RAW_DATA_DIR, "KDDTest+.txt")
    
    df_train = pd.read_csv(train_path, header=None, names=NSL_KDD_COLUMNS)
    df_test = pd.read_csv(test_path, header=None, names=NSL_KDD_COLUMNS)
    
    print(f"KDDTrain+ total rows: {len(df_train)}, columns: {df_train.shape[1]}")
    print(f"KDDTest+  total rows: {len(df_test)}, columns: {df_test.shape[1]}")
    
    # Map 5-class labels
    df_train["label_clean"] = df_train["label"].astype(str).str.strip()
    df_test["label_clean"] = df_test["label"].astype(str).str.strip()
    
    df_train["class_5"] = df_train["label_clean"].map(lambda x: NSL_KDD_5CLASS_MAP.get(x, "Unknown"))
    df_test["class_5"] = df_test["label_clean"].map(lambda x: NSL_KDD_5CLASS_MAP.get(x, "Unknown"))
    
    # 1. Class distributions
    train_dist = df_train["class_5"].value_counts().to_dict()
    test_dist = df_test["class_5"].value_counts().to_dict()
    
    print("\n--- 5-Class Distributions ---")
    print(f"{'Class':<12} | {'Train Count':<12} | {'Train %':<10} | {'Test Count':<12} | {'Test %':<10}")
    print("-" * 65)
    for c in ["Normal", "DoS", "Probe", "R2L", "U2R", "Unknown"]:
        tr_c = train_dist.get(c, 0)
        te_c = test_dist.get(c, 0)
        print(f"{c:<12} | {tr_c:<12} | {tr_c/len(df_train)*100:<9.2f}% | {te_c:<12} | {te_c/len(df_test)*100:<9.2f}%")
        
    # 2. Attack variant comparison
    train_attacks = set(df_train[df_train["class_5"] != "Normal"]["label_clean"].unique())
    test_attacks = set(df_test[df_test["class_5"] != "Normal"]["label_clean"].unique())
    
    unseen_in_test = test_attacks - train_attacks
    print(f"\nUnique attack types in Train: {len(train_attacks)}")
    print(f"Unique attack types in Test : {len(test_attacks)}")
    print(f"Novel / Unseen attack types in Test: {len(unseen_in_test)}")
    
    unseen_flow_count = len(df_test[df_test["label_clean"].isin(unseen_in_test)])
    print(f"Total flows belonging to unseen attacks in Test: {unseen_flow_count} ({unseen_flow_count/len(df_test)*100:.2f}% of test set)")
    
    unseen_breakdown = {}
    for atk in sorted(unseen_in_test):
        cnt = int(np.sum(df_test["label_clean"] == atk))
        fam = NSL_KDD_5CLASS_MAP.get(atk, "Unknown")
        unseen_breakdown[atk] = {"count": cnt, "family": fam}
        print(f"  - {atk:<18} (Family: {fam:<6}): {cnt} flows")
        
    # 3. Duplicate checks
    feature_cols = [c for c in NSL_KDD_COLUMNS if c not in ["label", "difficulty"]]
    tr_dup_rows = df_train.duplicated().sum()
    tr_dup_feats = df_train.duplicated(subset=feature_cols).sum()
    te_dup_rows = df_test.duplicated().sum()
    te_dup_feats = df_test.duplicated(subset=feature_cols).sum()
    print(f"\nDuplicate feature vectors in Train: {tr_dup_feats} / {len(df_train)}")
    print(f"Duplicate feature vectors in Test : {te_dup_feats} / {len(df_test)}")
    
    # 4. Categorical cardinality
    print("\nCategorical Feature Cardinality:")
    for col in ["protocol_type", "service", "flag"]:
        tr_vals = set(df_train[col].unique())
        te_vals = set(df_test[col].unique())
        diff = te_vals - tr_vals
        print(f"  - {col:<15}: Train={len(tr_vals)}, Test={len(te_vals)}, In Test but not Train={diff}")
        
    # 5. Constant / Low variance features in Train
    num_cols = df_train.select_dtypes(include=[np.number]).columns
    num_cols = [c for c in num_cols if c != "difficulty"]
    stds = df_train[num_cols].std()
    zero_std = stds[stds == 0].index.tolist()
    print(f"\nZero-variance numerical features in Train: {zero_std}")
    
    # 6. Detailed Error Analysis of v1.2 Model
    print("\n" + "=" * 70)
    print("PROFILING v1.2 MODEL PREDICTION ERRORS ON KDDTEST+")
    print("=" * 70)
    
    v12_model = joblib.load(os.path.join(V12_DIR, "best_model.joblib"))
    v12_preproc = joblib.load(os.path.join(V12_DIR, "preprocessor.joblib"))
    v12_selector = joblib.load(os.path.join(V12_DIR, "feature_selector.joblib"))
    v12_encoder = joblib.load(os.path.join(V12_DIR, "label_encoder.joblib"))
    
    classes = list(v12_encoder.classes_)
    normal_idx = classes.index("Normal")
    attack_indices = [i for i in range(len(classes)) if i != normal_idx]
    
    X_test_proc = v12_preproc.transform(df_test)
    X_test_sel = v12_selector.transform(X_test_proc)
    
    probs = v12_model.predict_proba(X_test_sel)
    p_norm = probs[:, normal_idx]
    p_atk = 1.0 - p_norm
    
    # v1.2 decision rule:
    # if p_atk >= 0.45: argmax over attack classes
    # elif p_norm < 0.75: suspicious (routed to highest attack)
    # else: normal
    preds_v12 = np.zeros(len(df_test), dtype=int)
    is_susp = np.zeros(len(df_test), dtype=bool)
    for i in range(len(df_test)):
        if p_atk[i] >= 0.45:
            atk_p = [(c_idx, probs[i, c_idx]) for c_idx in attack_indices]
            preds_v12[i] = max(atk_p, key=lambda x: x[1])[0]
        elif p_norm[i] < 0.75:
            is_susp[i] = True
            atk_p = [(c_idx, probs[i, c_idx]) for c_idx in attack_indices]
            preds_v12[i] = max(atk_p, key=lambda x: x[1])[0]
        else:
            preds_v12[i] = normal_idx
            
    y_test_true = np.array([classes.index(v) if v in classes else normal_idx for v in df_test["class_5"]])
    
    # Confusion Matrix
    cm = pd.DataFrame(
        confusion_matrix(y_test_true, preds_v12, labels=range(len(classes))),
        index=[f"True_{c}" for c in classes],
        columns=[f"Pred_{c}" for c in classes]
    )
    print("\nv1.2 Full Confusion Matrix:")
    print(cm)
    
    # Failure breakdown by Attack Family
    print("\nAttack-Family Error Profiling in v1.2:")
    family_errors = {}
    for fam in ["DoS", "Probe", "R2L", "U2R"]:
        f_idx = classes.index(fam)
        fam_mask = (y_test_true == f_idx)
        total_fam = int(np.sum(fam_mask))
        pred_fam = preds_v12[fam_mask]
        
        tp = int(np.sum(pred_fam == f_idx))
        fn_to_normal = int(np.sum(pred_fam == normal_idx))
        confused_other_atk = total_fam - tp - fn_to_normal
        susp_in_fam = int(np.sum(fam_mask & is_susp))
        
        family_errors[fam] = {
            "total": total_fam,
            "correct_family": tp,
            "missed_as_normal": fn_to_normal,
            "confused_with_other_attack": confused_other_atk,
            "flagged_suspicious": susp_in_fam,
            "recall": tp / total_fam if total_fam > 0 else 0,
            "miss_rate_to_normal": fn_to_normal / total_fam if total_fam > 0 else 0
        }
        print(f"  {fam:<6}: Total={total_fam:<5} | Correct={tp:<5} ({tp/total_fam*100:<5.1f}%) | Missed as Normal={fn_to_normal:<5} ({fn_to_normal/total_fam*100:<5.1f}%) | Confused with Other Attack={confused_other_atk:<4}")

    # Inspect Normal false alarms
    norm_mask = (y_test_true == normal_idx)
    norm_total = int(np.sum(norm_mask))
    norm_preds = preds_v12[norm_mask]
    norm_correct = int(np.sum(norm_preds == normal_idx))
    norm_fp = int(np.sum(norm_preds != normal_idx))
    norm_susp = int(np.sum(norm_mask & is_susp))
    print(f"\nNormal Traffic Profiling:")
    print(f"  Total Normal : {norm_total}")
    print(f"  Correct Normal: {norm_correct} ({norm_correct/norm_total*100:.2f}%)")
    print(f"  False Alarms  : {norm_fp} ({norm_fp/norm_total*100:.2f}%) [of which {norm_susp} in uncertainty zone]")

    # Analysis of R2L failures
    r2l_mask = (df_test["class_5"] == "R2L")
    r2l_df = df_test[r2l_mask].copy()
    r2l_df["pred"] = [classes[p] for p in preds_v12[r2l_mask]]
    r2l_df["p_norm"] = p_norm[r2l_mask]
    r2l_df["p_atk"] = p_atk[r2l_mask]
    
    print("\nR2L Error Breakdown by Specific Attack Variant:")
    r2l_by_atk = r2l_df.groupby("label_clean")["pred"].value_counts().unstack().fillna(0).astype(int)
    print(r2l_by_atk)
    
    # Save audit report data
    audit_data = {
        "train_samples": len(df_train),
        "test_samples": len(df_test),
        "train_class_dist": train_dist,
        "test_class_dist": test_dist,
        "unseen_attack_count": len(unseen_in_test),
        "unseen_flow_count": unseen_flow_count,
        "unseen_breakdown": unseen_breakdown,
        "zero_variance_features": zero_std,
        "v12_family_errors": family_errors,
        "v12_normal_errors": {
            "total": norm_total, "correct": norm_correct, "false_positives": norm_fp, "suspicious": norm_susp
        }
    }
    
    with open(os.path.join(OUT_DIR, "data_audit_summary.json"), "w") as f:
        json.dump(audit_data, f, indent=2)
        
    print(f"\nAudit data saved to {os.path.join(OUT_DIR, 'data_audit_summary.json')}")

if __name__ == "__main__":
    run_audit()
