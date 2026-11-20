"""
Phase 19.7 - Step 7: Evaluate Expert Ensemble on KDDTest+
=========================================================
Evaluates:
- Base 5-Class Cost-Sensitive Model + R2L Specialist + U2R Specialist.
- Compares against v1.2 baseline.
"""

import os
import sys
import json
import numpy as np
import pandas as pd
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report, confusion_matrix
from xgboost import XGBClassifier

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
RAW_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "raw")
OUT_DIR = os.path.join(os.path.dirname(__file__), "results")

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

def run_test():
    print("=" * 70)
    print("TESTING EXPERT ENSEMBLE ON KDDTEST+")
    print("=" * 70)
    
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
    
    y_train = np.array([classes.index(v) if v in classes else normal_idx for v in df_train["class_5"]])
    y_test = np.array([classes.index(v) if v in classes else normal_idx for v in df_test["class_5"]])
    
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
    
    # 1. Base Model
    print("Training Base 5-Class Model on KDDTrain+...")
    w_base = compute_sample_weight('balanced', y_train)
    w_base[y_train == r2l_idx] *= 3.5
    w_base[y_train == u2r_idx] *= 8.0
    w_base = np.clip(w_base, 0.1, 150.0)
    
    m_base = XGBClassifier(
        tree_method="hist", max_depth=8, learning_rate=0.08, n_estimators=120,
        subsample=0.85, colsample_bytree=0.85, n_jobs=2, random_state=42
    )
    m_base.fit(X_train, y_train, sample_weight=w_base)
    probs_base = m_base.predict_proba(X_test)
    
    # 2. R2L Specialist
    print("Training R2L Specialist on KDDTrain+...")
    y_tr_r2l = (y_train == r2l_idx).astype(int)
    w_r2l = compute_sample_weight('balanced', y_tr_r2l)
    m_r2l = XGBClassifier(
        tree_method="hist", max_depth=6, learning_rate=0.08, n_estimators=120,
        subsample=0.85, colsample_bytree=0.85, n_jobs=2, random_state=42
    )
    m_r2l.fit(X_train, y_tr_r2l, sample_weight=w_r2l)
    p_r2l_test = m_r2l.predict_proba(X_test)[:, 1]
    
    # 3. U2R Specialist
    print("Training U2R Specialist on KDDTrain+...")
    y_tr_u2r = (y_train == u2r_idx).astype(int)
    w_u2r = compute_sample_weight('balanced', y_tr_u2r)
    m_u2r = XGBClassifier(
        tree_method="hist", max_depth=5, learning_rate=0.08, n_estimators=100,
        subsample=0.85, colsample_bytree=0.85, n_jobs=2, random_state=42
    )
    m_u2r.fit(X_train, y_tr_u2r, sample_weight=w_u2r)
    p_u2r_test = m_u2r.predict_proba(X_test)[:, 1]
    
    # Decision logic
    TAU_R2L_GATE = 0.50
    TAU_U2R_GATE = 0.60
    TAU_ATTACK = 0.45
    TAU_CERTAINTY = 0.75
    
    preds = np.zeros(len(df_test), dtype=int)
    is_susp = np.zeros(len(df_test), dtype=bool)
    
    for i in range(len(df_test)):
        p_norm = probs_base[i, normal_idx]
        p_atk = 1.0 - p_norm
        
        if p_u2r_test[i] >= TAU_U2R_GATE:
            preds[i] = u2r_idx
        elif p_r2l_test[i] >= TAU_R2L_GATE:
            preds[i] = r2l_idx
        elif p_atk >= TAU_ATTACK:
            atk_probs = [(c_idx, probs_base[i, c_idx]) for c_idx in range(len(classes)) if c_idx != normal_idx]
            preds[i] = max(atk_probs, key=lambda x: x[1])[0]
        elif p_norm < TAU_CERTAINTY:
            is_susp[i] = True
            atk_probs = [(c_idx, probs_base[i, c_idx]) for c_idx in range(len(classes)) if c_idx != normal_idx]
            preds[i] = max(atk_probs, key=lambda x: x[1])[0]
        else:
            preds[i] = normal_idx
            
    acc = accuracy_score(y_test, preds)
    m_p, m_r, m_f1, _ = precision_recall_fscore_support(y_test, preds, average='macro', zero_division=0)
    wt_p, wt_r, wt_f1, _ = precision_recall_fscore_support(y_test, preds, average='weighted', zero_division=0)
    
    y_true_bin = (y_test != normal_idx).astype(int)
    y_alert_bin = ((preds != normal_idx) | is_susp).astype(int)
    
    tp = int(np.sum((y_true_bin == 1) & (y_alert_bin == 1)))
    fn = int(np.sum((y_true_bin == 1) & (y_alert_bin == 0)))
    fp = int(np.sum((y_true_bin == 0) & (y_alert_bin == 1)))
    tn = int(np.sum((y_true_bin == 0) & (y_alert_bin == 0)))
    
    atk_rec = tp / (tp + fn)
    atk_fnr = fn / (tp + fn)
    ben_fpr = fp / (fp + tn)
    
    rep = classification_report(y_test, preds, target_names=classes, output_dict=True, zero_division=0)
    r2l_rec = rep.get("R2L", {}).get("recall", 0.0)
    u2r_rec = rep.get("U2R", {}).get("recall", 0.0)
    dos_rec = rep.get("DoS", {}).get("recall", 0.0)
    probe_rec = rep.get("Probe", {}).get("recall", 0.0)
    
    print("\n--- RESULTS ON KDDTEST+ ---")
    print(f"Accuracy         : {acc*100:.4f}%")
    print(f"Weighted F1      : {wt_f1:.4f}")
    print(f"Macro F1         : {m_f1:.4f}")
    print(f"Attack Recall    : {atk_rec*100:.4f}% (TP={tp}, FN={fn})")
    print(f"Attack FNR       : {atk_fnr*100:.4f}%")
    print(f"Benign FPR       : {ben_fpr*100:.4f}% (FP={fp})")
    print(f"R2L Recall       : {r2l_rec*100:.2f}% (Support: 2885, TP={rep['R2L']['support']*r2l_rec:.0f})")
    print(f"U2R Recall       : {u2r_rec*100:.2f}% (Support: 67, TP={rep['U2R']['support']*u2r_rec:.0f})")
    print(f"DoS Recall       : {dos_rec*100:.2f}%")
    print(f"Probe Recall     : {probe_rec*100:.2f}%")
    
    cm = pd.DataFrame(
        confusion_matrix(y_test, preds, labels=range(len(classes))),
        index=[f"True_{c}" for c in classes],
        columns=[f"Pred_{c}" for c in classes]
    )
    print("\nConfusion Matrix:")
    print(cm)

if __name__ == "__main__":
    run_test()
