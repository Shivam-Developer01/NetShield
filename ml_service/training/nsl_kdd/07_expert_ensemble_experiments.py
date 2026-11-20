"""
Phase 19.7 - Step 6: Specialized Expert Head & Multi-Model Architecture
========================================================================
Research hypothesis:
- A single flat classifier struggles to distinguish R2L (995 samples) from Normal (67,343 samples) on services like ftp, telnet, pop_3.
- By training a dedicated R2L/U2R Specialist Head on interactive services and fusing its calibrated probability with the base model, we can detect remote/local intrusion attempts without hurting DoS/Probe or Normal traffic.

Protocol:
- KDDTrain+ 80% Train, 20% Val.
- Tested strictly on validation split first.
"""

import os
import sys
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report
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

def run_expert_experiments():
    print("=" * 70)
    print("PHASE 19.7 - STEP 6: SPECIALIZED INTRUSION EXPERT VALIDATION")
    print("=" * 70)
    
    train_path = os.path.join(RAW_DATA_DIR, "KDDTrain+.txt")
    df = pd.read_csv(train_path, header=None, names=NSL_KDD_COLUMNS)
    df["label_clean"] = df["label"].astype(str).str.strip()
    df["class_5"] = df["label_clean"].map(lambda x: NSL_KDD_5CLASS_MAP.get(x, "Unknown"))
    
    train_idx, val_idx = train_test_split(
        np.arange(len(df)),
        test_size=0.20,
        random_state=42,
        stratify=df["class_5"]
    )
    
    df_train = df.iloc[train_idx].copy().reset_index(drop=True)
    df_val = df.iloc[val_idx].copy().reset_index(drop=True)
    
    classes = ["DoS", "Normal", "Probe", "R2L", "U2R"]
    normal_idx = classes.index("Normal")
    r2l_idx = classes.index("R2L")
    u2r_idx = classes.index("U2R")
    
    y_train = np.array([classes.index(v) if v in classes else normal_idx for v in df_train["class_5"]])
    y_val = np.array([classes.index(v) if v in classes else normal_idx for v in df_val["class_5"]])
    
    # Feature transform
    df_train_ext = add_derived_features(df_train)
    df_val_ext = add_derived_features(df_val)
    
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
    X_val = col_trans.transform(df_val_ext)
    
    # 1. Base 5-Class Cost-Sensitive Model (Improved v1.2 style on full feature set)
    print("Training Base 5-Class Cost-Sensitive Model...")
    w_base = compute_sample_weight('balanced', y_train)
    w_base[y_train == r2l_idx] *= 3.5
    w_base[y_train == u2r_idx] *= 8.0
    w_base = np.clip(w_base, 0.1, 150.0)
    
    m_base = XGBClassifier(
        tree_method="hist",
        max_depth=8,
        learning_rate=0.08,
        n_estimators=120,
        subsample=0.85,
        colsample_bytree=0.85,
        n_jobs=2,
        random_state=42
    )
    m_base.fit(X_train, y_train, sample_weight=w_base)
    probs_base = m_base.predict_proba(X_val)
    
    # 2. Train R2L Specialist (Trained specifically on binary: R2L vs Non-R2L)
    print("Training Dedicated R2L Specialist...")
    y_tr_r2l_bin = (y_train == r2l_idx).astype(int)
    w_r2l = compute_sample_weight('balanced', y_tr_r2l_bin)
    m_r2l = XGBClassifier(
        tree_method="hist",
        max_depth=6,
        learning_rate=0.08,
        n_estimators=120,
        subsample=0.85,
        colsample_bytree=0.85,
        n_jobs=2,
        random_state=42
    )
    m_r2l.fit(X_train, y_tr_r2l_bin, sample_weight=w_r2l)
    p_r2l_val = m_r2l.predict_proba(X_val)[:, 1]
    
    # 3. Train U2R Specialist (Trained specifically on binary: U2R vs Non-U2R)
    print("Training Dedicated U2R Specialist...")
    y_tr_u2r_bin = (y_train == u2r_idx).astype(int)
    w_u2r = compute_sample_weight('balanced', y_tr_u2r_bin)
    m_u2r = XGBClassifier(
        tree_method="hist",
        max_depth=5,
        learning_rate=0.08,
        n_estimators=100,
        subsample=0.85,
        colsample_bytree=0.85,
        n_jobs=2,
        random_state=42
    )
    m_u2r.fit(X_train, y_tr_u2r_bin, sample_weight=w_u2r)
    p_u2r_val = m_u2r.predict_proba(X_val)[:, 1]
    
    # 4. Evaluate Fusion on Validation Split
    print("\n--- Evaluating Fusion Strategies on Validation Data ---")
    
    # Sweep expert gating thresholds:
    for tau_r2l_gate in [0.50, 0.60, 0.70, 0.80]:
        for tau_u2r_gate in [0.50, 0.60, 0.70]:
            preds = np.zeros(len(df_val), dtype=int)
            is_susp = np.zeros(len(df_val), dtype=bool)
            
            for i in range(len(df_val)):
                p_norm = probs_base[i, normal_idx]
                p_atk = 1.0 - p_norm
                
                # Check specialists first
                if p_u2r_val[i] >= tau_u2r_gate:
                    preds[i] = u2r_idx
                elif p_r2l_val[i] >= tau_r2l_gate:
                    preds[i] = r2l_idx
                elif p_atk >= 0.40:
                    # Argmax over attack classes in base
                    atk_probs = [(c_idx, probs_base[i, c_idx]) for c_idx in range(len(classes)) if c_idx != normal_idx]
                    preds[i] = max(atk_probs, key=lambda x: x[1])[0]
                elif p_norm < 0.75:
                    is_susp[i] = True
                    atk_probs = [(c_idx, probs_base[i, c_idx]) for c_idx in range(len(classes)) if c_idx != normal_idx]
                    preds[i] = max(atk_probs, key=lambda x: x[1])[0]
                else:
                    preds[i] = normal_idx
                    
            acc = accuracy_score(y_val, preds)
            m_p, m_r, m_f1, _ = precision_recall_fscore_support(y_val, preds, average='macro', zero_division=0)
            
            y_true_bin = (y_val != normal_idx).astype(int)
            y_alert_bin = ((preds != normal_idx) | is_susp).astype(int)
            
            tp = int(np.sum((y_true_bin == 1) & (y_alert_bin == 1)))
            fn = int(np.sum((y_true_bin == 1) & (y_alert_bin == 0)))
            fp = int(np.sum((y_true_bin == 0) & (y_alert_bin == 1)))
            tn = int(np.sum((y_true_bin == 0) & (y_alert_bin == 0)))
            
            atk_rec = tp / (tp + fn)
            ben_fpr = fp / (fp + tn)
            
            rep = classification_report(y_val, preds, target_names=classes, output_dict=True, zero_division=0)
            r2l_rec = rep.get("R2L", {}).get("recall", 0.0)
            u2r_rec = rep.get("U2R", {}).get("recall", 0.0)
            
            print(f"Gate(R2L>={tau_r2l_gate:.2f}, U2R>={tau_u2r_gate:.2f}): Acc={acc*100:.2f}%, Atk Recall={atk_rec*100:.2f}%, Benign FPR={ben_fpr*100:.4f}%, Macro F1={m_f1:.4f}, R2L Rec={r2l_rec*100:.1f}%, U2R Rec={u2r_rec*100:.1f}%")

if __name__ == "__main__":
    run_expert_experiments()
