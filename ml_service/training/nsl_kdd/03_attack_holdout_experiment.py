"""
Phase 19.7 - Step 3: Unseen Attack Generalization Benchmark on KDDTrain+
==========================================================================
To simulate zero-day generalization WITHOUT touching KDDTest+:
- Partition KDDTrain+ into Known Attacks (Train) and Holdout Attacks (Validation).
- Holdout attack types: 'teardrop' (DoS), 'nmap' (Probe), 'warezclient' (R2L), 'rootkit' (U2R).
- Compare how different architectures generalize to completely unseen attacks.
"""

import os
import sys
import json
import numpy as np
import pandas as pd
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

CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']
EXCLUDE_COLS = ['label', 'difficulty_level', 'num_outbound_cmds', 'label_clean', 'class_5', 'is_holdout']

HOLDOUT_ATTACKS = {'teardrop', 'nmap', 'warezclient', 'rootkit'}

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

def run_holdout_experiment():
    print("=" * 70)
    print("PHASE 19.7 - STEP 3: UNSEEN ATTACK GENERALIZATION EXPERIMENT")
    print("=" * 70)
    
    train_path = os.path.join(RAW_DATA_DIR, "KDDTrain+.txt")
    df = pd.read_csv(train_path, header=None, names=NSL_KDD_COLUMNS)
    df["label_clean"] = df["label"].astype(str).str.strip()
    df["class_5"] = df["label_clean"].map(lambda x: NSL_KDD_5CLASS_MAP.get(x, "Unknown"))
    
    # Partition: holdout attacks vs known
    df["is_holdout"] = df["label_clean"].isin(HOLDOUT_ATTACKS)
    
    # Train: 80% of known samples
    # Val: 20% of known samples + 100% of holdout attack samples
    df_known = df[~df["is_holdout"]].copy()
    df_holdout_atks = df[df["is_holdout"]].copy()
    
    print(f"Known attacks/normal rows: {len(df_known)}")
    print(f"Holdout attack rows ({HOLDOUT_ATTACKS}): {len(df_holdout_atks)}")
    for atk in sorted(HOLDOUT_ATTACKS):
        print(f"  - {atk:<15}: {int(np.sum(df['label_clean'] == atk))} flows")
        
    np.random.seed(42)
    known_tr_idx = df_known.sample(frac=0.80, random_state=42).index
    known_val_idx = df_known.index.difference(known_tr_idx)
    
    df_train = df_known.loc[known_tr_idx].copy().reset_index(drop=True)
    df_val = pd.concat([df_known.loc[known_val_idx], df_holdout_atks], ignore_index=True).reset_index(drop=True)
    
    print(f"Experimental Train Split: {len(df_train)} rows (0 holdout attacks)")
    print(f"Experimental Val Split  : {len(df_val)} rows (includes {len(df_holdout_atks)} completely unseen attack flows)")
    
    classes = ["DoS", "Normal", "Probe", "R2L", "U2R"]
    normal_idx = classes.index("Normal")
    atk_classes = ["DoS", "Probe", "R2L", "U2R"]
    atk_to_orig = [classes.index(c) for c in atk_classes]
    
    y_train = np.array([classes.index(v) if v in classes else normal_idx for v in df_train["class_5"]])
    y_val = np.array([classes.index(v) if v in classes else normal_idx for v in df_val["class_5"]])
    is_holdout_val = df_val["is_holdout"].values
    
    # Preprocessor
    df_train_feats = add_derived_features(df_train)
    df_val_feats = add_derived_features(df_val)
    
    cat_cols = [c for c in CATEGORICAL_COLS if c in df_train_feats.columns]
    num_cols = [c for c in df_train_feats.columns if c not in cat_cols and c not in EXCLUDE_COLS]
    
    col_trans = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), num_cols),
            ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), cat_cols)
        ],
        remainder='drop'
    )
    col_trans.fit(df_train_feats)
    
    X_train = col_trans.transform(df_train_feats)
    X_val = col_trans.transform(df_val_feats)
    
    # ------------------------------------------------------------------
    # Model 1: Flat 5-Class Multiclass (v1.2 baseline architecture)
    # ------------------------------------------------------------------
    print("\nTraining Model 1: Flat 5-Class Multiclass with Sample Weights...")
    w_flat = compute_sample_weight('balanced', y_train)
    w_flat[y_train == classes.index("R2L")] *= 3.0
    w_flat[y_train == classes.index("U2R")] *= 6.0
    
    m_flat = XGBClassifier(tree_method="hist", n_estimators=100, max_depth=8, learning_rate=0.1, n_jobs=2, random_state=42)
    m_flat.fit(X_train, y_train, sample_weight=w_flat)
    probs_flat = m_flat.predict_proba(X_val)
    
    # Evaluate Model 1:
    preds_flat = np.argmax(probs_flat, axis=1)
    
    # ------------------------------------------------------------------
    # Model 2: Two-Stage Cascade with Tuned Binary Stage 1 Threshold
    # ------------------------------------------------------------------
    print("Training Model 2: Two-Stage Cascade (Binary Attack Detector + Multiclass Router)...")
    y_train_bin = (y_train != normal_idx).astype(int)
    w_bin = compute_sample_weight('balanced', y_train_bin)
    
    m_bin = XGBClassifier(tree_method="hist", n_estimators=100, max_depth=7, learning_rate=0.08, n_jobs=2, random_state=42)
    m_bin.fit(X_train, y_train_bin, sample_weight=w_bin)
    p_atk_s1 = m_bin.predict_proba(X_val)[:, 1]
    
    # Router on attacks
    atk_mask_tr = (y_train != normal_idx)
    y_tr_atk = y_train[atk_mask_tr]
    y_tr_atk_c = np.array([atk_classes.index(classes[v]) for v in y_tr_atk])
    w_atk = compute_sample_weight('balanced', y_tr_atk_c)
    w_atk[y_tr_atk_c == atk_classes.index("R2L")] *= 3.0
    w_atk[y_tr_atk_c == atk_classes.index("U2R")] *= 6.0
    
    m_router = XGBClassifier(tree_method="hist", n_estimators=100, max_depth=8, learning_rate=0.08, n_jobs=2, random_state=42)
    m_router.fit(X_train[atk_mask_tr], y_tr_atk_c, sample_weight=w_atk)
    probs_router = m_router.predict_proba(X_val)
    
    # Decision rule with tau=0.40:
    preds_twostage = np.zeros(len(df_val), dtype=int)
    for i in range(len(df_val)):
        if p_atk_s1[i] >= 0.40:
            preds_twostage[i] = atk_to_orig[np.argmax(probs_router[i])]
        else:
            preds_twostage[i] = normal_idx
            
    # ------------------------------------------------------------------
    # Model 3: Two-Stage + Specialized R2L / U2R Expert
    # ------------------------------------------------------------------
    print("Training Model 3: Two-Stage Cascade + Specialized R2L/U2R Expert...")
    y_tr_r2l = (y_train == classes.index("R2L")).astype(int)
    w_r2l = compute_sample_weight('balanced', y_tr_r2l)
    m_r2l_expert = XGBClassifier(tree_method="hist", n_estimators=100, max_depth=6, learning_rate=0.08, n_jobs=2, random_state=42)
    m_r2l_expert.fit(X_train, y_tr_r2l, sample_weight=w_r2l)
    p_r2l = m_r2l_expert.predict_proba(X_val)[:, 1]
    
    preds_expert = np.zeros(len(df_val), dtype=int)
    for i in range(len(df_val)):
        if p_atk_s1[i] >= 0.35:
            if p_r2l[i] >= 0.55:
                preds_expert[i] = classes.index("R2L")
            else:
                preds_expert[i] = atk_to_orig[np.argmax(probs_router[i])]
        else:
            if p_r2l[i] >= 0.80:
                preds_expert[i] = classes.index("R2L")
            else:
                preds_expert[i] = normal_idx

    # ------------------------------------------------------------------
    # Compare Generalization on Unseen Holdout Attacks
    # ------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("UNSEEN HOLDOUT ATTACK DETECTION PERFORMANCE (Zero-Day Simulation):")
    print("=" * 70)
    
    def eval_model(preds, name):
        # Overall
        y_true_bin = (y_val != normal_idx).astype(int)
        y_pred_bin = (preds != normal_idx).astype(int)
        tp = int(np.sum((y_true_bin == 1) & (y_pred_bin == 1)))
        fn = int(np.sum((y_true_bin == 1) & (y_pred_bin == 0)))
        fp = int(np.sum((y_true_bin == 0) & (y_pred_bin == 1)))
        tn = int(np.sum((y_true_bin == 0) & (y_pred_bin == 0)))
        
        overall_rec = tp / (tp + fn)
        overall_fpr = fp / (fp + tn)
        
        # Unseen attacks specifically
        unseen_tp = int(np.sum((is_holdout_val) & (y_pred_bin == 1)))
        unseen_total = int(np.sum(is_holdout_val))
        unseen_rec = unseen_tp / unseen_total
        
        # Breakdown by attack
        atk_recs = {}
        for atk in sorted(HOLDOUT_ATTACKS):
            m = (df_val["label_clean"] == atk).values
            tot = int(np.sum(m))
            c_tp = int(np.sum(m & (y_pred_bin == 1)))
            atk_recs[atk] = {"recall": c_tp / tot if tot > 0 else 0, "count": tot, "tp": c_tp}
            
        print(f"\n[{name}]")
        print(f"  Overall Attack Recall: {overall_rec*100:.2f}% | Benign FPR: {overall_fpr*100:.4f}%")
        print(f"  UNSEEN Attack Recall : {unseen_rec*100:.2f}% ({unseen_tp}/{unseen_total})")
        for atk, d in atk_recs.items():
            print(f"    - {atk:<14}: {d['recall']*100:.1f}% ({d['tp']}/{d['count']})")
        return {
            "overall_recall": overall_rec, "benign_fpr": overall_fpr,
            "unseen_recall": unseen_rec, "breakdown": atk_recs
        }

    res1 = eval_model(preds_flat, "1. Flat 5-Class Multiclass")
    res2 = eval_model(preds_twostage, "2. Two-Stage Cascade (Tau=0.40)")
    res3 = eval_model(preds_expert, "3. Two-Stage + Specialized R2L Expert")
    
    with open(os.path.join(OUT_DIR, "unseen_holdout_results.json"), "w") as f:
        json.dump({"m1_flat": res1, "m2_twostage": res2, "m3_expert": res3}, f, indent=2)

if __name__ == "__main__":
    run_holdout_experiment()
