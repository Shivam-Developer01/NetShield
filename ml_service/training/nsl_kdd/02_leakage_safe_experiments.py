"""
Phase 19.7 - Step 2: Leakage-Safe Feature Engineering & Model Experiments
==========================================================================
Protocol:
- KDDTrain+ is split strictly into 80% Train (100,778) and 20% Val (25,195) with stratification.
- KDDTest+ is NEVER touched during this phase.
- Compares:
  1. Feature Schemas: Baseline 37 vs Extended 41 + Derived Network Features.
  2. Model Algorithms: XGBoost Hist vs HistGradientBoosting vs RandomForest.
  3. Class Balancing & Cost Weights: Balanced vs Targeted R2L/U2R Multipliers.
  4. Decision Architectures: Flat 5-Class vs Two-Stage Binary+Router vs Cascaded R2L Expert.
  5. Validation Threshold Optimization.
"""

import os
import sys
import json
import time
import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, StandardScaler, LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix
)
from xgboost import XGBClassifier
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
RAW_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "raw")
OUT_DIR = os.path.join(os.path.dirname(__file__), "results")
os.makedirs(OUT_DIR, exist_ok=True)

sys.path.append(os.path.join(PROJECT_ROOT, "ml_service", "src", "preprocessing"))
from nsl_kdd_preprocessor import NSL_KDD_COLUMNS, NSL_KDD_5CLASS_MAP

# Ensure 'worm' is mapped to R2L in 5-class map
NSL_KDD_5CLASS_MAP['worm'] = 'R2L'

CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']
EXCLUDE_COLS = ['label', 'difficulty_level', 'num_outbound_cmds', 'label_clean', 'class_5']

def add_derived_features(df):
    """
    Computes legitimate derived flow features without inventing fake host information.
    All features are derived from available packet/connection statistics.
    """
    df = df.copy()
    
    # 1. Total bytes & Byte rate
    dur = df['duration'].clip(lower=0.0)
    src_b = df['src_bytes'].clip(lower=0.0)
    dst_b = df['dst_bytes'].clip(lower=0.0)
    
    df['total_bytes'] = src_b + dst_b
    df['bytes_per_sec'] = (df['total_bytes']) / (dur + 0.001)
    
    # 2. Byte asymmetry ratio
    df['src_to_dst_byte_ratio'] = (src_b + 1.0) / (dst_b + 1.0)
    df['dst_to_src_byte_ratio'] = (dst_b + 1.0) / (src_b + 1.0)
    
    # 3. Connection count rates
    cnt = df['count'].clip(lower=0.0)
    srv_cnt = df['srv_count'].clip(lower=0.0)
    df['count_per_sec'] = cnt / (dur + 0.001)
    df['srv_count_per_sec'] = srv_cnt / (dur + 0.001)
    
    # 4. Error symmetry
    s_err = df['serror_rate'].clip(lower=0.0, upper=1.0)
    r_err = df['rerror_rate'].clip(lower=0.0, upper=1.0)
    df['error_rate_diff'] = np.abs(s_err - r_err)
    df['total_error_rate'] = np.clip(s_err + r_err, 0.0, 1.0)
    
    # 5. Service rates interaction
    same_srv = df['same_srv_rate'].clip(lower=0.0, upper=1.0)
    diff_srv = df['diff_srv_rate'].clip(lower=0.0, upper=1.0)
    df['srv_diversity_ratio'] = diff_srv / (same_srv + 0.01)
    
    # 6. Host destination rate interaction
    dst_same = df['dst_host_same_srv_rate'].clip(lower=0.0, upper=1.0)
    dst_diff = df['dst_host_diff_srv_rate'].clip(lower=0.0, upper=1.0)
    df['dst_host_srv_ratio'] = dst_diff / (dst_same + 0.01)
    
    # 7. Protocol risk flags (indicator for interactive remote shells / login services)
    interactive_services = {
        'telnet', 'ftp', 'ftp_data', 'ssh', 'login', 'exec', 'rje', 'shell',
        'klogin', 'kshell', 'pop_3', 'imap4', 'smtp', 'finger'
    }
    df['is_interactive_service'] = df['service'].map(lambda s: 1.0 if str(s).strip() in interactive_services else 0.0)
    
    # 8. Failed login indicator (if logged_in is 0 but attempts made)
    df['failed_login_indicator'] = ((df['logged_in'] == 0) & (df['num_failed_logins'] > 0)).astype(float)
    
    # 9. Compromised or root activity indicator
    df['compromised_indicator'] = ((df['num_compromised'] > 0) | (df['root_shell'] == 1) | (df['su_attempted'] > 0)).astype(float)
    
    return df

def build_preprocessing_pipeline(df_train_raw, use_derived=True):
    """
    Builds a leakage-free Sklearn ColumnTransformer fitted strictly on training fold.
    """
    if use_derived:
        df_feats = add_derived_features(df_train_raw)
    else:
        df_feats = df_train_raw.copy()
        
    X_train_clean = df_feats.drop(columns=[c for c in EXCLUDE_COLS if c in df_feats.columns], errors='ignore')
    
    cat_cols = [c for c in CATEGORICAL_COLS if c in X_train_clean.columns]
    num_cols = [c for c in X_train_clean.columns if c not in cat_cols]
    
    col_trans = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), num_cols),
            ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), cat_cols)
        ],
        remainder='drop'
    )
    
    col_trans.fit(X_train_clean)
    
    # Get feature names
    cat_enc = col_trans.named_transformers_['cat']
    cat_feature_names = cat_enc.get_feature_names_out(cat_cols).tolist()
    all_feature_names = num_cols + cat_feature_names
    
    return col_trans, all_feature_names, num_cols, cat_cols

def evaluate_on_val(y_val, y_val_preds, probs, normal_idx, classes, title=""):
    """Computes comprehensive validation metrics."""
    acc = accuracy_score(y_val, y_val_preds)
    macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(y_val, y_val_preds, average='macro', zero_division=0)
    wt_p, wt_r, wt_f1, _ = precision_recall_fscore_support(y_val, y_val_preds, average='weighted', zero_division=0)
    
    y_true_bin = (y_val != normal_idx).astype(int)
    y_pred_bin = (y_val_preds != normal_idx).astype(int)
    
    tp = int(np.sum((y_true_bin == 1) & (y_pred_bin == 1)))
    tn = int(np.sum((y_true_bin == 0) & (y_pred_bin == 0)))
    fp = int(np.sum((y_true_bin == 0) & (y_pred_bin == 1)))
    fn = int(np.sum((y_true_bin == 1) & (y_pred_bin == 0)))
    
    atk_recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    atk_fnr = fn / (tp + fn) if (tp + fn) > 0 else 0
    ben_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    rep = classification_report(y_val, y_val_preds, target_names=classes, output_dict=True, zero_division=0)
    r2l_rec = rep.get("R2L", {}).get("recall", 0.0)
    u2r_rec = rep.get("U2R", {}).get("recall", 0.0)
    dos_rec = rep.get("DoS", {}).get("recall", 0.0)
    probe_rec = rep.get("Probe", {}).get("recall", 0.0)
    
    res = {
        "title": title,
        "accuracy": acc,
        "weighted_f1": wt_f1,
        "macro_f1": macro_f1,
        "macro_recall": macro_r,
        "attack_recall": atk_recall,
        "attack_fnr": atk_fnr,
        "benign_fpr": ben_fpr,
        "r2l_recall": r2l_rec,
        "u2r_recall": u2r_rec,
        "dos_recall": dos_rec,
        "probe_recall": probe_rec,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn
    }
    return res

def run_experiments():
    print("=" * 70)
    print("PHASE 19.7 - STEP 2: LEAKAGE-SAFE VALIDATION EXPERIMENTS")
    print("=" * 70)
    
    # 1. Load KDDTrain+
    train_path = os.path.join(RAW_DATA_DIR, "KDDTrain+.txt")
    df_kdd_train = pd.read_csv(train_path, header=None, names=NSL_KDD_COLUMNS)
    
    df_kdd_train["label_clean"] = df_kdd_train["label"].astype(str).str.strip()
    df_kdd_train["class_5"] = df_kdd_train["label_clean"].map(lambda x: NSL_KDD_5CLASS_MAP.get(x, "Unknown"))
    
    # 2. Fixed Stratified Train/Validation Split (80/20)
    print("Splitting KDDTrain+ into 80% Train and 20% Validation (Stratified on 5 classes)...")
    train_indices, val_indices = train_test_split(
        np.arange(len(df_kdd_train)),
        test_size=0.20,
        random_state=42,
        stratify=df_kdd_train["class_5"]
    )
    
    df_tr = df_kdd_train.iloc[train_indices].copy().reset_index(drop=True)
    df_val = df_kdd_train.iloc[val_indices].copy().reset_index(drop=True)
    
    print(f"Training split rows  : {len(df_tr)} (80.0%)")
    print(f"Validation split rows: {len(df_val)} (20.0%)")
    
    # Encode classes
    classes = ["DoS", "Normal", "Probe", "R2L", "U2R"]
    normal_idx = classes.index("Normal")
    r2l_idx = classes.index("R2L")
    u2r_idx = classes.index("U2R")
    attack_indices = [i for i in range(len(classes)) if i != normal_idx]
    
    y_tr = np.array([classes.index(v) if v in classes else normal_idx for v in df_tr["class_5"]])
    y_val = np.array([classes.index(v) if v in classes else normal_idx for v in df_val["class_5"]])
    
    # Prepare Feature Sets
    print("\nFitting Leakage-Free Preprocessors on Training Split Only...")
    # Setup A: Raw 37/41 Baseline features
    pipe_raw, feat_names_raw, _, _ = build_preprocessing_pipeline(df_tr, use_derived=False)
    X_tr_raw = pipe_raw.transform(df_tr)
    X_val_raw = pipe_raw.transform(df_val)
    print(f"Baseline Feature Matrix: {X_tr_raw.shape[1]} columns")
    
    # Setup B: Extended Derived Network features
    pipe_ext, feat_names_ext, _, _ = build_preprocessing_pipeline(df_tr, use_derived=True)
    X_tr_ext = pipe_ext.transform(add_derived_features(df_tr))
    X_val_ext = pipe_ext.transform(add_derived_features(df_val))
    print(f"Extended Feature Matrix (with derived network features): {X_tr_ext.shape[1]} columns")
    
    results = []
    
    # -------------------------------------------------------------
    # EXP 1: Baseline Architecture on Raw vs Extended Features
    # -------------------------------------------------------------
    print("\n--- EXPERIMENT 1: BASELINE MODEL ON RAW VS EXTENDED FEATURES ---")
    weights_balanced = compute_sample_weight('balanced', y_tr)
    
    # 1A. Raw Baseline
    print("Training 1A: XGBoost Hist on Raw Baseline Features...")
    m_1a = XGBClassifier(tree_method="hist", n_estimators=100, max_depth=8, learning_rate=0.1, subsample=0.8, n_jobs=2, random_state=42)
    m_1a.fit(X_tr_raw, y_tr, sample_weight=weights_balanced)
    probs_1a = m_1a.predict_proba(X_val_raw)
    preds_1a = np.argmax(probs_1a, axis=1)
    res_1a = evaluate_on_val(y_val, preds_1a, probs_1a, normal_idx, classes, title="1A. Baseline Features (Argmax)")
    results.append(res_1a)
    print(f"  -> Acc: {res_1a['accuracy']*100:.2f}%, Atk Recall: {res_1a['attack_recall']*100:.2f}%, Macro F1: {res_1a['macro_f1']:.4f}, R2L Rec: {res_1a['r2l_recall']*100:.1f}%, U2R Rec: {res_1a['u2r_recall']*100:.1f}%")

    # 1B. Extended Features
    print("Training 1B: XGBoost Hist on Extended Features...")
    m_1b = XGBClassifier(tree_method="hist", n_estimators=100, max_depth=8, learning_rate=0.1, subsample=0.8, n_jobs=2, random_state=42)
    m_1b.fit(X_tr_ext, y_tr, sample_weight=weights_balanced)
    probs_1b = m_1b.predict_proba(X_val_ext)
    preds_1b = np.argmax(probs_1b, axis=1)
    res_1b = evaluate_on_val(y_val, preds_1b, probs_1b, normal_idx, classes, title="1B. Extended Features (Argmax)")
    results.append(res_1b)
    print(f"  -> Acc: {res_1b['accuracy']*100:.2f}%, Atk Recall: {res_1b['attack_recall']*100:.2f}%, Macro F1: {res_1b['macro_f1']:.4f}, R2L Rec: {res_1b['r2l_recall']*100:.1f}%, U2R Rec: {res_1b['u2r_recall']*100:.1f}%")

    # -------------------------------------------------------------
    # EXP 2: Algorithm Comparison (Extended Features)
    # -------------------------------------------------------------
    print("\n--- EXPERIMENT 2: ALGORITHM COMPARISON ---")
    
    # 2A. HistGradientBoostingClassifier (LightGBM-style)
    print("Training 2A: Scikit-Learn HistGradientBoostingClassifier...")
    m_2a = HistGradientBoostingClassifier(max_iter=100, max_depth=8, learning_rate=0.1, random_state=42)
    m_2a.fit(X_tr_ext, y_tr, sample_weight=weights_balanced)
    probs_2a = m_2a.predict_proba(X_val_ext)
    preds_2a = np.argmax(probs_2a, axis=1)
    res_2a = evaluate_on_val(y_val, preds_2a, probs_2a, normal_idx, classes, title="2A. HistGradientBoosting (Scikit-Learn)")
    results.append(res_2a)
    print(f"  -> Acc: {res_2a['accuracy']*100:.2f}%, Atk Recall: {res_2a['attack_recall']*100:.2f}%, Macro F1: {res_2a['macro_f1']:.4f}, R2L Rec: {res_2a['r2l_recall']*100:.1f}%")

    # -------------------------------------------------------------
    # EXP 3: Targeted Class Weighting & Cost-Sensitive R2L/U2R
    # -------------------------------------------------------------
    print("\n--- EXPERIMENT 3: TARGETED MINORITY BOOSTING ---")
    # In Train split, R2L has 796 samples (0.79%), U2R has 42 samples (0.04%).
    # We test targeted multiplier factors: R2L x 3.0, U2R x 8.0
    weights_targeted = compute_sample_weight('balanced', y_tr)
    weights_targeted[y_tr == r2l_idx] *= 3.5
    weights_targeted[y_tr == u2r_idx] *= 8.0
    weights_targeted = np.clip(weights_targeted, 0.1, 150.0)
    
    print("Training 3A: XGBoost with Targeted R2L(x3.5)/U2R(x8.0) Sample Weights...")
    m_3a = XGBClassifier(tree_method="hist", n_estimators=120, max_depth=8, learning_rate=0.08, subsample=0.85, colsample_bytree=0.85, n_jobs=2, random_state=42)
    m_3a.fit(X_tr_ext, y_tr, sample_weight=weights_targeted)
    probs_3a = m_3a.predict_proba(X_val_ext)
    preds_3a = np.argmax(probs_3a, axis=1)
    res_3a = evaluate_on_val(y_val, preds_3a, probs_3a, normal_idx, classes, title="3A. Targeted Weights (Argmax)")
    results.append(res_3a)
    print(f"  -> Acc: {res_3a['accuracy']*100:.2f}%, Atk Recall: {res_3a['attack_recall']*100:.2f}%, Macro F1: {res_3a['macro_f1']:.4f}, R2L Rec: {res_3a['r2l_recall']*100:.1f}%, U2R Rec: {res_3a['u2r_recall']*100:.1f}%")

    # -------------------------------------------------------------
    # EXP 4: Hierarchical Cascade (Two-Stage vs Specialized R2L)
    # -------------------------------------------------------------
    print("\n--- EXPERIMENT 4: HIERARCHICAL & SPECIALIZED CASCADE ---")
    
    # Stage 1: Binary Attack Detector (Normal vs Attack)
    y_tr_binary = (y_tr != normal_idx).astype(int)
    y_val_binary = (y_val != normal_idx).astype(int)
    weights_bin = compute_sample_weight('balanced', y_tr_binary)
    
    print("Training Stage 1: Dedicated Binary Attack Detector...")
    stage1_binary = XGBClassifier(tree_method="hist", n_estimators=100, max_depth=7, learning_rate=0.1, n_jobs=2, random_state=42)
    stage1_binary.fit(X_tr_ext, y_tr_binary, sample_weight=weights_bin)
    probs_s1_val = stage1_binary.predict_proba(X_val_ext)[:, 1] # Probability of Attack
    
    # Stage 2: 4-Attack Family Classifier (Trained strictly on attack samples)
    atk_train_mask = (y_tr != normal_idx)
    X_tr_atk = X_tr_ext[atk_train_mask]
    y_tr_atk = y_tr[atk_train_mask]
    
    # Attack classes: DoS, Probe, R2L, U2R (contiguous 0..3)
    atk_classes = ["DoS", "Probe", "R2L", "U2R"]
    atk_to_orig = [classes.index(c) for c in atk_classes]
    y_tr_atk_contig = np.array([atk_classes.index(classes[v]) for v in y_tr_atk])
    
    weights_stage2 = compute_sample_weight('balanced', y_tr_atk_contig)
    r2l_contig_idx = atk_classes.index("R2L")
    u2r_contig_idx = atk_classes.index("U2R")
    weights_stage2[y_tr_atk_contig == r2l_contig_idx] *= 3.0
    weights_stage2[y_tr_atk_contig == u2r_contig_idx] *= 6.0
    
    print("Training Stage 2: Attack Taxonomic Router (DoS, Probe, R2L, U2R)...")
    stage2_router = XGBClassifier(tree_method="hist", n_estimators=100, max_depth=8, learning_rate=0.08, n_jobs=2, random_state=42)
    stage2_router.fit(X_tr_atk, y_tr_atk_contig, sample_weight=weights_stage2)
    probs_s2_val = stage2_router.predict_proba(X_val_ext)
    
    # Stage 3 Specialist: Dedicated Binary Detector for R2L
    # Distinguishes R2L from (Normal + other attacks on interactive services)
    print("Training Stage 3 Specialist: Dedicated R2L Specialist Detector...")
    y_tr_r2l = (y_tr == r2l_idx).astype(int)
    weights_r2l = compute_sample_weight('balanced', y_tr_r2l)
    r2l_specialist = XGBClassifier(tree_method="hist", n_estimators=100, max_depth=6, learning_rate=0.08, n_jobs=2, random_state=42)
    r2l_specialist.fit(X_tr_ext, y_tr_r2l, sample_weight=weights_r2l)
    probs_r2l_val = r2l_specialist.predict_proba(X_val_ext)[:, 1]

    # Evaluate Cascaded Architecture at default thresholds
    preds_cascade_default = np.zeros(len(df_val), dtype=int)
    for i in range(len(df_val)):
        if probs_s1_val[i] >= 0.50:
            # Check if specialist flags R2L with high confidence
            if probs_r2l_val[i] >= 0.65:
                preds_cascade_default[i] = r2l_idx
            else:
                preds_cascade_default[i] = atk_to_orig[np.argmax(probs_s2_val[i])]
        else:
            # If Stage 1 is negative, check if R2L specialist strongly overrides
            if probs_r2l_val[i] >= 0.85:
                preds_cascade_default[i] = r2l_idx
            else:
                preds_cascade_default[i] = normal_idx
                
    res_4a = evaluate_on_val(y_val, preds_cascade_default, probs_3a, normal_idx, classes, title="4A. Hierarchical Cascade + R2L Specialist (Default Tau=0.5)")
    results.append(res_4a)
    print(f"  -> Acc: {res_4a['accuracy']*100:.2f}%, Atk Recall: {res_4a['attack_recall']*100:.2f}%, Macro F1: {res_4a['macro_f1']:.4f}, R2L Rec: {res_4a['r2l_recall']*100:.1f}%, U2R Rec: {res_4a['u2r_recall']*100:.1f}%")

    # -------------------------------------------------------------
    # EXP 5: Threshold Sweep on Validation Data (Phase 9)
    # -------------------------------------------------------------
    print("\n--- EXPERIMENT 5: VALIDATION THRESHOLD OPTIMIZATION ---")
    sweep_data = []
    print(f"{'Tau_Atk':<8} | {'Tau_R2L':<8} | {'Accuracy':<10} | {'Atk Recall':<12} | {'Atk FNR':<10} | {'Benign FPR':<12} | {'Macro F1':<10} | {'R2L Rec':<8} | {'U2R Rec':<8}")
    print("-" * 95)
    
    best_config = None
    best_objective_score = -1.0
    
    for tau_atk in [0.35, 0.40, 0.45, 0.50]:
        for tau_r2l in [0.50, 0.55, 0.60, 0.65, 0.70]:
            preds_sw = np.zeros(len(df_val), dtype=int)
            for i in range(len(df_val)):
                if probs_s1_val[i] >= tau_atk:
                    if probs_r2l_val[i] >= tau_r2l:
                        preds_sw[i] = r2l_idx
                    else:
                        preds_sw[i] = atk_to_orig[np.argmax(probs_s2_val[i])]
                else:
                    if probs_r2l_val[i] >= 0.85: # Strong override
                        preds_sw[i] = r2l_idx
                    else:
                        preds_sw[i] = normal_idx
                        
            eval_sw = evaluate_on_val(y_val, preds_sw, probs_3a, normal_idx, classes, title=f"Sweep tau_atk={tau_atk}, tau_r2l={tau_r2l}")
            sweep_data.append(eval_sw)
            
            # Objective: Maximize Attack Recall + Macro F1 + R2L Recall, penalized if Benign FPR > 1.0%
            obj_score = eval_sw["attack_recall"] * 0.4 + eval_sw["macro_f1"] * 0.3 + eval_sw["r2l_recall"] * 0.3
            if eval_sw["benign_fpr"] > 0.01:
                obj_score -= (eval_sw["benign_fpr"] - 0.01) * 5.0
                
            if obj_score > best_objective_score:
                best_objective_score = obj_score
                best_config = (tau_atk, tau_r2l, eval_sw)
                
            print(f"{tau_atk:<8.2f} | {tau_r2l:<8.2f} | {eval_sw['accuracy']*100:<9.2f}% | {eval_sw['attack_recall']*100:<11.2f}% | {eval_sw['attack_fnr']*100:<9.2f}% | {eval_sw['benign_fpr']*100:<11.4f}% | {eval_sw['macro_f1']:<10.4f} | {eval_sw['r2l_recall']*100:<7.1f}% | {eval_sw['u2r_recall']*100:<7.1f}%")
            
    print(f"\nOptimal Validation Configuration:")
    print(f"  Tau Attack: {best_config[0]}, Tau R2L: {best_config[1]}")
    print(f"  Validation Acc: {best_config[2]['accuracy']*100:.2f}%, Atk Recall: {best_config[2]['attack_recall']*100:.2f}%, Macro F1: {best_config[2]['macro_f1']:.4f}, Benign FPR: {best_config[2]['benign_fpr']*100:.4f}%")

    # Save summary of all experiment results
    exp_summary = {
        "experiments": results,
        "best_sweep_config": {
            "tau_atk": best_config[0],
            "tau_r2l": best_config[1],
            "validation_metrics": best_config[2]
        }
    }
    with open(os.path.join(OUT_DIR, "validation_experiments_summary.json"), "w") as f:
        json.dump(exp_summary, f, indent=2)
        
    print(f"\nAll validation experiments completed and saved to {os.path.join(OUT_DIR, 'validation_experiments_summary.json')}")

if __name__ == "__main__":
    run_experiments()
