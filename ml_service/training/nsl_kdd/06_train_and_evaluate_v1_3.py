"""
Phase 19.7 - Step 5: Train & Evaluate NetShield-NSLKDD-HierarchicalCascade-v1.3
================================================================================
Trained on KDDTrain+ (125,973 rows) with validated hyperparameters and thresholds.
Evaluated on KDDTest+ (22,544 rows) exactly ONCE.
Outputs:
- Full classification metrics (closed-set, detection-oriented, and strict).
- Per-class precision, recall, F1.
- Attack family breakdown (DoS, Probe, R2L, U2R).
- Unseen variant detection.
- Model artifacts saved to artifacts/v1.3/nsl_kdd/.
"""

import os
import sys
import json
import time
import numpy as np
import pandas as pd
import joblib

from sklearn.preprocessing import OneHotEncoder, StandardScaler, LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix
)
from xgboost import XGBClassifier

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
RAW_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "raw")
V13_DIR = os.path.join(PROJECT_ROOT, "artifacts", "v1.3", "nsl_kdd")
OUT_DIR = os.path.join(os.path.dirname(__file__), "results")
os.makedirs(V13_DIR, exist_ok=True)
os.makedirs(OUT_DIR, exist_ok=True)

sys.path.append(os.path.join(PROJECT_ROOT, "ml_service", "src", "preprocessing"))
from nsl_kdd_preprocessor import NSL_KDD_COLUMNS, NSL_KDD_5CLASS_MAP

NSL_KDD_5CLASS_MAP['worm'] = 'R2L'
CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']
EXCLUDE_COLS = ['label', 'difficulty_level', 'num_outbound_cmds', 'label_clean', 'class_5']

def add_derived_features(df):
    df = df.copy()
    dur = df['duration'].clip(lower=0.0)
    src_b = df['src_bytes'].clip(lower=0.0)
    dst_b = df['dst_bytes'].clip(lower=0.0)
    
    df['total_bytes'] = src_b + dst_b
    df['bytes_per_sec'] = (df['total_bytes']) / (dur + 0.001)
    df['src_to_dst_byte_ratio'] = (src_b + 1.0) / (dst_b + 1.0)
    df['dst_to_src_byte_ratio'] = (dst_b + 1.0) / (src_b + 1.0)
    
    cnt = df['count'].clip(lower=0.0)
    srv_cnt = df['srv_count'].clip(lower=0.0)
    df['count_per_sec'] = cnt / (dur + 0.001)
    df['srv_count_per_sec'] = srv_cnt / (dur + 0.001)
    
    s_err = df['serror_rate'].clip(lower=0.0, upper=1.0)
    r_err = df['rerror_rate'].clip(lower=0.0, upper=1.0)
    df['error_rate_diff'] = np.abs(s_err - r_err)
    df['total_error_rate'] = np.clip(s_err + r_err, 0.0, 1.0)
    
    same_srv = df['same_srv_rate'].clip(lower=0.0, upper=1.0)
    diff_srv = df['diff_srv_rate'].clip(lower=0.0, upper=1.0)
    df['srv_diversity_ratio'] = diff_srv / (same_srv + 0.01)
    
    dst_same = df['dst_host_same_srv_rate'].clip(lower=0.0, upper=1.0)
    dst_diff = df['dst_host_diff_srv_rate'].clip(lower=0.0, upper=1.0)
    df['dst_host_srv_ratio'] = dst_diff / (dst_same + 0.01)
    
    interactive_services = {
        'telnet', 'ftp', 'ftp_data', 'ssh', 'login', 'exec', 'rje', 'shell',
        'klogin', 'kshell', 'pop_3', 'imap4', 'smtp', 'finger'
    }
    df['is_interactive_service'] = df['service'].map(lambda s: 1.0 if str(s).strip() in interactive_services else 0.0)
    df['failed_login_indicator'] = ((df['logged_in'] == 0) & (df['num_failed_logins'] > 0)).astype(float)
    df['compromised_indicator'] = ((df['num_compromised'] > 0) | (df['root_shell'] == 1) | (df['su_attempted'] > 0)).astype(float)
    
    return df

def run_v1_3_pipeline():
    print("=" * 70)
    print("PHASE 19.7 - STEP 5: TRAINING & FINAL EVALUATION OF NSL-KDD v1.3")
    print("=" * 70)
    
    # 1. Load Datasets
    train_path = os.path.join(RAW_DATA_DIR, "KDDTrain+.txt")
    test_path = os.path.join(RAW_DATA_DIR, "KDDTest+.txt")
    
    df_train = pd.read_csv(train_path, header=None, names=NSL_KDD_COLUMNS)
    df_test = pd.read_csv(test_path, header=None, names=NSL_KDD_COLUMNS)
    
    df_train["label_clean"] = df_train["label"].astype(str).str.strip()
    df_test["label_clean"] = df_test["label"].astype(str).str.strip()
    
    df_train["class_5"] = df_train["label_clean"].map(lambda x: NSL_KDD_5CLASS_MAP.get(x, "Unknown"))
    df_test["class_5"] = df_test["label_clean"].map(lambda x: NSL_KDD_5CLASS_MAP.get(x, "Unknown"))
    
    classes = ["DoS", "Normal", "Probe", "R2L", "U2R"]
    normal_idx = classes.index("Normal")
    r2l_idx = classes.index("R2L")
    u2r_idx = classes.index("U2R")
    atk_classes = ["DoS", "Probe", "R2L", "U2R"]
    atk_to_orig = [classes.index(c) for c in atk_classes]
    
    y_train = np.array([classes.index(v) if v in classes else normal_idx for v in df_train["class_5"]])
    y_test = np.array([classes.index(v) if v in classes else normal_idx for v in df_test["class_5"]])
    
    print(f"Training rows: {len(df_train)}, Test rows: {len(df_test)}")
    
    # 2. Build Preprocessor Strictly on KDDTrain+
    print("\nFitting Leakage-Free Preprocessor strictly on KDDTrain+...")
    df_train_ext = add_derived_features(df_train)
    df_test_ext = add_derived_features(df_test)
    
    cat_cols = [c for c in CATEGORICAL_COLS if c in df_train_ext.columns]
    num_cols = [c for c in df_train_ext.columns if c not in cat_cols and c not in EXCLUDE_COLS]
    
    col_trans = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), num_cols),
            ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), cat_cols)
        ],
        remainder='drop'
    )
    col_trans.fit(df_train_ext)
    
    X_train = col_trans.transform(df_train_ext)
    X_test = col_trans.transform(df_test_ext)
    
    cat_enc = col_trans.named_transformers_['cat']
    feature_names = num_cols + cat_enc.get_feature_names_out(cat_cols).tolist()
    print(f"Feature matrix columns: {len(feature_names)}")
    
    # 3. Train Stage 1: Binary Attack Detector
    print("\nTraining Stage 1 Binary Attack Detector...")
    y_train_bin = (y_train != normal_idx).astype(int)
    w_bin = compute_sample_weight('balanced', y_train_bin)
    
    t0 = time.time()
    s1_binary = XGBClassifier(
        tree_method="hist",
        max_depth=7,
        learning_rate=0.08,
        n_estimators=120,
        subsample=0.85,
        colsample_bytree=0.85,
        n_jobs=2,
        random_state=42
    )
    s1_binary.fit(X_train, y_train_bin, sample_weight=w_bin)
    t_s1 = time.time() - t0
    print(f"Stage 1 trained in {t_s1:.2f}s.")
    
    # 4. Train Stage 2: Attack Taxonomic Router
    print("Training Stage 2 Attack Taxonomic Router (DoS, Probe, R2L, U2R)...")
    atk_mask_tr = (y_train != normal_idx)
    X_tr_atk = X_train[atk_mask_tr]
    y_tr_atk = y_train[atk_mask_tr]
    y_tr_atk_c = np.array([atk_classes.index(classes[v]) for v in y_tr_atk])
    
    w_atk = compute_sample_weight('balanced', y_tr_atk_c)
    w_atk[y_tr_atk_c == atk_classes.index("R2L")] *= 4.0
    w_atk[y_tr_atk_c == atk_classes.index("U2R")] *= 10.0
    w_atk = np.clip(w_atk, 0.1, 150.0)
    
    t0 = time.time()
    s2_router = XGBClassifier(
        tree_method="hist",
        max_depth=8,
        learning_rate=0.08,
        n_estimators=120,
        subsample=0.85,
        colsample_bytree=0.85,
        n_jobs=2,
        random_state=42
    )
    s2_router.fit(X_tr_atk, y_tr_atk_c, sample_weight=w_atk)
    t_s2 = time.time() - t0
    print(f"Stage 2 trained in {t_s2:.2f}s.")
    
    # 5. Frozen Thresholds Selected in Phase 4 Validation
    TAU_ATTACK = 0.35
    TAU_CERTAINTY = 0.70
    
    print(f"\nApplying Frozen Thresholds: tau_attack={TAU_ATTACK}, tau_certainty={TAU_CERTAINTY}")
    
    # 6. Execute Final Untouched Test Set Evaluation
    print(f"Evaluating v1.3 on KDDTest+ ({len(df_test)} samples) exactly ONCE...")
    t0 = time.time()
    p_atk_s1 = s1_binary.predict_proba(X_test)[:, 1] # P(Attack)
    p_norm_s1 = 1.0 - p_atk_s1
    probs_s2 = s2_router.predict_proba(X_test)        # (N, 4)
    t_inf = (time.time() - t0) / len(df_test) * 1000.0
    
    preds_test = np.zeros(len(df_test), dtype=int)
    is_susp_test = np.zeros(len(df_test), dtype=bool)
    is_confident_atk = np.zeros(len(df_test), dtype=bool)
    
    for i in range(len(df_test)):
        if p_atk_s1[i] >= TAU_ATTACK:
            best_atk = atk_to_orig[np.argmax(probs_s2[i])]
            preds_test[i] = best_atk
            is_confident_atk[i] = True
        elif p_norm_s1[i] < TAU_CERTAINTY:
            is_susp_test[i] = True
            best_atk = atk_to_orig[np.argmax(probs_s2[i])]
            preds_test[i] = best_atk
        else:
            preds_test[i] = normal_idx
            
    # 7. Compute Metrics
    # A. Detection / Alert Metrics (Counting Suspicious as Alerted)
    y_true_binary = (y_test != normal_idx).astype(int)
    y_alert_binary = ((preds_test != normal_idx) | is_susp_test).astype(int)
    
    tp_alert = int(np.sum((y_true_binary == 1) & (y_alert_binary == 1)))
    tn_alert = int(np.sum((y_true_binary == 0) & (y_alert_binary == 0)))
    fp_alert = int(np.sum((y_true_binary == 0) & (y_alert_binary == 1)))
    fn_alert = int(np.sum((y_true_binary == 1) & (y_alert_binary == 0)))
    
    alert_recall = tp_alert / (tp_alert + fn_alert)
    alert_fnr = fn_alert / (tp_alert + fn_alert)
    alert_fpr = fp_alert / (fp_alert + tn_alert)
    
    # B. Confident-Only Metrics
    tp_conf = int(np.sum((y_true_binary == 1) & (is_confident_atk)))
    fn_conf = int(np.sum((y_true_binary == 1) & (~is_confident_atk)))
    fp_conf = int(np.sum((y_true_binary == 0) & (is_confident_atk)))
    tn_conf = int(np.sum((y_true_binary == 0) & (~is_confident_atk)))
    
    conf_recall = tp_conf / (tp_conf + fn_conf)
    conf_fnr = fn_conf / (tp_conf + fn_conf)
    conf_fpr = fp_conf / (fp_conf + tn_conf)
    
    # C. Multi-class Metrics (with Routing)
    acc = accuracy_score(y_test, preds_test)
    macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(y_test, preds_test, average='macro', zero_division=0)
    wt_p, wt_r, wt_f1, _ = precision_recall_fscore_support(y_test, preds_test, average='weighted', zero_division=0)
    
    rep = classification_report(y_test, preds_test, target_names=classes, output_dict=True, zero_division=0)
    r2l_rec = rep.get("R2L", {}).get("recall", 0.0)
    u2r_rec = rep.get("U2R", {}).get("recall", 0.0)
    dos_rec = rep.get("DoS", {}).get("recall", 0.0)
    probe_rec = rep.get("Probe", {}).get("recall", 0.0)
    
    # D. Unseen Attack Variants
    known_kdd_train_attacks = {
        'back', 'land', 'neptune', 'pod', 'smurf', 'teardrop',
        'satan', 'ipsweep', 'nmap', 'portsweep',
        'guess_passwd', 'ftp_write', 'imap', 'phf', 'multihop', 'warezmaster', 'warezclient', 'spy',
        'buffer_overflow', 'loadmodule', 'rootkit', 'perl'
    }
    raw_labels = df_test["label_clean"].values
    is_unseen = np.array([lbl not in known_kdd_train_attacks and lbl != 'normal' for lbl in raw_labels])
    unseen_total = int(np.sum(is_unseen))
    unseen_alerted = int(np.sum(is_unseen & (y_alert_binary == 1)))
    unseen_conf = int(np.sum(is_unseen & (is_confident_atk)))
    unseen_recall = unseen_alerted / unseen_total if unseen_total > 0 else 0
    unseen_fnr = 1.0 - unseen_recall
    
    # E. Confusion Matrix
    cm = pd.DataFrame(
        confusion_matrix(y_test, preds_test, labels=range(len(classes))),
        index=[f"True_{c}" for c in classes],
        columns=[f"Pred_{c}" for c in classes]
    )
    
    print("\n" + "=" * 70)
    print("NSL-KDD v1.3 FINAL EVALUATION RESULTS ON KDDTEST+:")
    print("=" * 70)
    print(f"Accuracy                     : {acc*100:.4f}%")
    print(f"Weighted F1                  : {wt_f1:.4f}")
    print(f"Macro F1                     : {macro_f1:.4f}")
    print(f"Macro Recall                 : {macro_r:.4f}")
    print(f"Detection / Alert Recall     : {alert_recall*100:.4f}% (TP={tp_alert}, FN={fn_alert})")
    print(f"Attack FNR (Miss Rate)       : {alert_fnr*100:.4f}%")
    print(f"Benign FPR (False Alarms)    : {alert_fpr*100:.4f}% (FP={fp_alert})")
    print(f"Confident Attack Recall      : {conf_recall*100:.4f}% (TP={tp_conf}, FN={fn_conf})")
    print(f"Attack Family Recalls:")
    print(f"  - DoS Recall               : {dos_rec*100:.2f}%")
    print(f"  - Probe Recall             : {probe_rec*100:.2f}%")
    print(f"  - R2L Recall               : {r2l_rec*100:.2f}%")
    print(f"  - U2R Recall               : {u2r_rec*100:.2f}%")
    print(f"Unseen Variant Coverage      : {unseen_recall*100:.2f}% (Miss Rate: {unseen_fnr*100:.2f}%)")
    print(f"Suspicious Flows Intercepted : {int(np.sum(is_susp_test))} flows")
    print(f"Mean Inference Latency       : {t_inf:.4f} ms/flow")
    
    print("\nConfusion Matrix:")
    print(cm)
    
    # 8. Save v1.3 Model Bundle to artifacts/v1.3/nsl_kdd/
    print("\nSaving versioned v1.3 artifacts to artifacts/v1.3/nsl_kdd/...")
    
    bundle_s1_s2 = {
        "stage1_binary": s1_binary,
        "stage2_router": s2_router,
        "atk_classes": atk_classes,
        "atk_to_orig": atk_to_orig,
        "normal_idx": normal_idx,
        "tau_attack": TAU_ATTACK,
        "tau_certainty": TAU_CERTAINTY
    }
    joblib.dump(bundle_s1_s2, os.path.join(V13_DIR, "best_model.joblib"))
    joblib.dump(col_trans, os.path.join(V13_DIR, "preprocessor.joblib"))
    
    # Dummy selector to maintain pipeline compatibility
    class IdentitySelector:
        def transform(self, X):
            return X
    joblib.dump(IdentitySelector(), os.path.join(V13_DIR, "feature_selector.joblib"))
    
    le = LabelEncoder()
    le.classes_ = np.array(classes)
    joblib.dump(le, os.path.join(V13_DIR, "label_encoder.joblib"))
    
    with open(os.path.join(V13_DIR, "feature_schema.json"), "w") as f:
        json.dump(feature_names, f, indent=2)
        
    meta_v13 = {
        "model_version": "NetShield-NSLKDD-HierarchicalCascade-v1.3",
        "dataset": "NSL-KDD",
        "decision_architecture": "Two-Stage Hierarchical Cascade (Stage 1 Binary Attack Filter + Stage 2 Taxonomic Router) with Extended Flow Telemetry",
        "feature_count": len(feature_names),
        "attack_threshold": TAU_ATTACK,
        "certainty_threshold": TAU_CERTAINTY,
        "test_samples": len(df_test),
        "evaluation_metrics": {
            "accuracy": acc,
            "weighted_f1": wt_f1,
            "macro_f1": macro_f1,
            "macro_recall": macro_r,
            "attack_recall": alert_recall,
            "attack_fnr": alert_fnr,
            "benign_fpr": alert_fpr,
            "confident_attack_recall": conf_recall,
            "confident_attack_fnr": conf_fnr,
            "r2l_recall": r2l_rec,
            "u2r_recall": u2r_rec,
            "dos_recall": dos_rec,
            "probe_recall": probe_rec,
            "unseen_variants_recall": unseen_recall,
            "unseen_variants_miss_rate": unseen_fnr,
            "tp": tp_alert, "tn": tn_alert, "fp": fp_alert, "fn": fn_alert,
            "intercepted_suspicious": int(np.sum(is_susp_test))
        },
        "per_class_metrics": rep
    }
    with open(os.path.join(V13_DIR, "metadata.json"), "w") as f:
        json.dump(meta_v13, f, indent=2)
        
    with open(os.path.join(OUT_DIR, "final_v1_3_results.json"), "w") as f:
        json.dump(meta_v13, f, indent=2)
        
    print(f"\nv1.3 artifacts successfully saved to {V13_DIR}")
    return meta_v13

if __name__ == "__main__":
    run_v1_3_pipeline()
