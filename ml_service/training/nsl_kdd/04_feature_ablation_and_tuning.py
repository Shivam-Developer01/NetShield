"""
Phase 19.7 - Step 4: Feature Ablation, Hyperparameter Tuning & Architecture Optimization
========================================================================================
Protocol:
- KDDTrain+ 80% Train, 20% Val (Stratified).
- Compares:
  1. Feature Sets (Raw 41 vs Extended 54 vs MI-Selected).
  2. Stage 1 Binary Hyperparameters & Regularization (Preventing Overconfidence on Normal).
  3. Stage 2 Multiclass Routing (Class-cost balancing for R2L & U2R).
  4. Validation Uncertainty Zone Calibration (Normal certainty threshold tau_c).
- Selection Objective:
  Maximize Validation Attack Recall + Macro F1 + R2L/U2R Sensitivity, while keeping Benign FPR <= 2.5%.
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

def run_tuning():
    print("=" * 70)
    print("PHASE 19.7 - STEP 4: TUNING & ARCHITECTURE EXPERIMENTS")
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
    atk_classes = ["DoS", "Probe", "R2L", "U2R"]
    atk_to_orig = [classes.index(c) for c in atk_classes]
    
    y_train = np.array([classes.index(v) if v in classes else normal_idx for v in df_train["class_5"]])
    y_val = np.array([classes.index(v) if v in classes else normal_idx for v in df_val["class_5"]])
    
    # Feature Engineering
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
    
    print(f"Total features after One-Hot Encoding: {X_train.shape[1]}")
    
    # -----------------------------------------------------------------
    # Stage 1: Binary Attack Detector Search
    # -----------------------------------------------------------------
    print("\n--- Tuning Stage 1 (Binary Normal vs Attack) ---")
    y_train_bin = (y_train != normal_idx).astype(int)
    y_val_bin = (y_val != normal_idx).astype(int)
    w_bin = compute_sample_weight('balanced', y_train_bin)
    
    # Test hyperparameter sets
    configs_s1 = [
        {"max_depth": 6, "learning_rate": 0.10, "n_estimators": 100, "colsample_bytree": 0.8},
        {"max_depth": 7, "learning_rate": 0.08, "n_estimators": 120, "colsample_bytree": 0.85},
        {"max_depth": 8, "learning_rate": 0.06, "n_estimators": 150, "colsample_bytree": 0.85},
    ]
    
    best_s1_model = None
    best_s1_f1 = -1.0
    best_s1_cfg = None
    
    for i, cfg in enumerate(configs_s1):
        m = XGBClassifier(
            tree_method="hist",
            max_depth=cfg["max_depth"],
            learning_rate=cfg["learning_rate"],
            n_estimators=cfg["n_estimators"],
            colsample_bytree=cfg["colsample_bytree"],
            subsample=0.85,
            n_jobs=2,
            random_state=42
        )
        m.fit(X_train, y_train_bin, sample_weight=w_bin)
        probs = m.predict_proba(X_val)[:, 1]
        preds = (probs >= 0.50).astype(int)
        
        acc = accuracy_score(y_val_bin, preds)
        p, r, f1, _ = precision_recall_fscore_support(y_val_bin, preds, average='binary', zero_division=0)
        fp = int(np.sum((y_val_bin == 0) & (preds == 1)))
        fpr = fp / int(np.sum(y_val_bin == 0))
        
        print(f"  S1 Config {i+1} ({cfg}): Acc={acc*100:.2f}%, Recall={r*100:.2f}%, Precision={p*100:.2f}%, F1={f1:.4f}, Benign FPR={fpr*100:.4f}%")
        if f1 > best_s1_f1:
            best_s1_f1 = f1
            best_s1_model = m
            best_s1_cfg = cfg
            
    # -----------------------------------------------------------------
    # Stage 2: Attack Taxonomic Router Search
    # -----------------------------------------------------------------
    print("\n--- Tuning Stage 2 (Taxonomic Router DoS, Probe, R2L, U2R) ---")
    atk_mask_tr = (y_train != normal_idx)
    X_tr_atk = X_train[atk_mask_tr]
    y_tr_atk = y_train[atk_mask_tr]
    y_tr_atk_c = np.array([atk_classes.index(classes[v]) for v in y_tr_atk])
    
    # Compare class weighting multipliers for R2L and U2R
    mult_configs = [
        {"r2l": 2.5, "u2r": 5.0},
        {"r2l": 4.0, "u2r": 10.0},
        {"r2l": 6.0, "u2r": 15.0}
    ]
    
    best_s2_model = None
    best_s2_score = -1.0
    best_s2_cfg = None
    
    for i, mult in enumerate(mult_configs):
        w_atk = compute_sample_weight('balanced', y_tr_atk_c)
        w_atk[y_tr_atk_c == atk_classes.index("R2L")] *= mult["r2l"]
        w_atk[y_tr_atk_c == atk_classes.index("U2R")] *= mult["u2r"]
        w_atk = np.clip(w_atk, 0.1, 150.0)
        
        m_r = XGBClassifier(
            tree_method="hist",
            max_depth=8,
            learning_rate=0.08,
            n_estimators=120,
            subsample=0.85,
            colsample_bytree=0.85,
            n_jobs=2,
            random_state=42
        )
        m_r.fit(X_tr_atk, y_tr_atk_c, sample_weight=w_atk)
        
        # Test routing on validation attacks
        atk_mask_val = (y_val != normal_idx)
        val_atk_preds = m_r.predict(X_val[atk_mask_val])
        val_atk_true = np.array([atk_classes.index(classes[v]) for v in y_val[atk_mask_val]])
        
        m_p, m_r_sc, m_f1, _ = precision_recall_fscore_support(val_atk_true, val_atk_preds, average='macro', zero_division=0)
        r2l_rec = precision_recall_fscore_support(val_atk_true, val_atk_preds, labels=[atk_classes.index("R2L")], average=None, zero_division=0)[1][0]
        u2r_rec = precision_recall_fscore_support(val_atk_true, val_atk_preds, labels=[atk_classes.index("U2R")], average=None, zero_division=0)[1][0]
        
        print(f"  S2 Config {i+1} (R2Lx{mult['r2l']}, U2Rx{mult['u2r']}): Macro F1={m_f1:.4f}, R2L Recall={r2l_rec*100:.1f}%, U2R Recall={u2r_rec*100:.1f}%")
        composite_score = m_f1 * 0.4 + r2l_rec * 0.3 + u2r_rec * 0.3
        if composite_score > best_s2_score:
            best_s2_score = composite_score
            best_s2_model = m_r
            best_s2_cfg = mult
            
    # -----------------------------------------------------------------
    # Stage 3: Joint Two-Stage Calibration & Threshold Optimization
    # -----------------------------------------------------------------
    print("\n--- Joint Two-Stage Threshold Optimization on Validation Data ---")
    p_atk_s1_val = best_s1_model.predict_proba(X_val)[:, 1]
    p_atk_s2_val = best_s2_model.predict_proba(X_val) # Shape: (N, 4)
    
    # Test grid of thresholds:
    # tau_attack in [0.30, 0.35, 0.40, 0.45]
    # tau_certainty in [0.70, 0.75, 0.80]
    
    sweep_results = []
    print(f"{'Tau_Atk':<8} | {'Tau_Cert':<8} | {'Accuracy':<10} | {'Atk Recall':<12} | {'Atk FNR':<10} | {'Benign FPR':<12} | {'Macro F1':<10} | {'R2L Rec':<8} | {'U2R Rec':<8}")
    print("-" * 95)
    
    optimal_joint_cfg = None
    best_joint_obj = -1.0
    
    for tau_a in [0.30, 0.35, 0.40, 0.45]:
        for tau_c in [0.65, 0.70, 0.75, 0.80]:
            preds_joint = np.zeros(len(df_val), dtype=int)
            is_susp_joint = np.zeros(len(df_val), dtype=bool)
            
            for i in range(len(df_val)):
                if p_atk_s1_val[i] >= tau_a:
                    best_atk = atk_to_orig[np.argmax(p_atk_s2_val[i])]
                    preds_joint[i] = best_atk
                elif (1.0 - p_atk_s1_val[i]) < tau_c:
                    # Uncertainty zone: flagged as suspicious, routed to best attack category
                    is_susp_joint[i] = True
                    best_atk = atk_to_orig[np.argmax(p_atk_s2_val[i])]
                    preds_joint[i] = best_atk
                else:
                    preds_joint[i] = normal_idx
                    
            # Compute metrics
            acc = accuracy_score(y_val, preds_joint)
            m_p, m_r, m_f1, _ = precision_recall_fscore_support(y_val, preds_joint, average='macro', zero_division=0)
            
            y_true_bin = (y_val != normal_idx).astype(int)
            y_pred_bin = (preds_joint != normal_idx).astype(int)
            tp = int(np.sum((y_true_bin == 1) & (y_pred_bin == 1)))
            fn = int(np.sum((y_true_bin == 1) & (y_pred_bin == 0)))
            fp = int(np.sum((y_true_bin == 0) & (y_pred_bin == 1)))
            tn = int(np.sum((y_true_bin == 0) & (y_pred_bin == 0)))
            
            atk_rec = tp / (tp + fn)
            atk_fnr = fn / (tp + fn)
            ben_fpr = fp / (fp + tn)
            
            rep = classification_report(y_val, preds_joint, target_names=classes, output_dict=True, zero_division=0)
            r2l_rec = rep.get("R2L", {}).get("recall", 0.0)
            u2r_rec = rep.get("U2R", {}).get("recall", 0.0)
            
            # Multi-objective score
            obj = atk_rec * 0.4 + m_f1 * 0.3 + r2l_rec * 0.2 + u2r_rec * 0.1
            if ben_fpr > 0.01:
                obj -= (ben_fpr - 0.01) * 3.0
                
            sweep_results.append({
                "tau_attack": tau_a, "tau_certainty": tau_c,
                "accuracy": acc, "macro_f1": m_f1,
                "attack_recall": atk_rec, "attack_fnr": atk_fnr, "benign_fpr": ben_fpr,
                "r2l_recall": r2l_rec, "u2r_recall": u2r_rec, "objective": obj
            })
            
            if obj > best_joint_obj:
                best_joint_obj = obj
                optimal_joint_cfg = (tau_a, tau_c, acc, atk_rec, atk_fnr, ben_fpr, m_f1, r2l_rec, u2r_rec)
                
            print(f"{tau_a:<8.2f} | {tau_c:<8.2f} | {acc*100:<9.2f}% | {atk_rec*100:<11.2f}% | {atk_fnr*100:<9.2f}% | {ben_fpr*100:<11.4f}% | {m_f1:<10.4f} | {r2l_rec*100:<7.1f}% | {u2r_rec*100:<7.1f}%")

    print(f"\nOptimal Validation Configuration Selected:")
    print(f"  Stage 1 Attack Threshold (tau_a): {optimal_joint_cfg[0]}")
    print(f"  Uncertainty Threshold    (tau_c): {optimal_joint_cfg[1]}")
    print(f"  Validation Acc: {optimal_joint_cfg[2]*100:.2f}%, Atk Recall: {optimal_joint_cfg[3]*100:.2f}%, Macro F1: {optimal_joint_cfg[6]:.4f}, Benign FPR: {optimal_joint_cfg[5]*100:.4f}%")

    # Save best models and configuration
    save_data = {
        "best_s1_config": best_s1_cfg,
        "best_s2_config": best_s2_cfg,
        "optimal_thresholds": {
            "tau_attack": optimal_joint_cfg[0],
            "tau_certainty": optimal_joint_cfg[1]
        },
        "validation_metrics": {
            "accuracy": optimal_joint_cfg[2],
            "attack_recall": optimal_joint_cfg[3],
            "attack_fnr": optimal_joint_cfg[4],
            "benign_fpr": optimal_joint_cfg[5],
            "macro_f1": optimal_joint_cfg[6],
            "r2l_recall": optimal_joint_cfg[7],
            "u2r_recall": optimal_joint_cfg[8]
        }
    }
    with open(os.path.join(OUT_DIR, "tuning_selection_summary.json"), "w") as f:
        json.dump(save_data, f, indent=2)
        
    print(f"Tuning selection summary saved to {os.path.join(OUT_DIR, 'tuning_selection_summary.json')}")

if __name__ == "__main__":
    run_tuning()
