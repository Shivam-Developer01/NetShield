import os
import sys
import json
import numpy as np
import pandas as pd
import joblib
from xgboost import XGBClassifier
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix
)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
RAW_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "raw")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
ARTIFACTS_DIR = os.path.join(PROJECT_ROOT, "artifacts")
V12_CICIDS_DIR = os.path.join(ARTIFACTS_DIR, "v1.2", "cicids2017")
V12_NSLKDD_DIR = os.path.join(ARTIFACTS_DIR, "v1.2", "nsl_kdd")

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(V12_CICIDS_DIR, exist_ok=True)
os.makedirs(V12_NSLKDD_DIR, exist_ok=True)

sys.path.append(os.path.join(PROJECT_ROOT, "ml_service", "src", "preprocessing"))
sys.path.append(os.path.join(PROJECT_ROOT, "ml_service", "src", "features"))
from nsl_kdd_preprocessor import NSL_KDD_COLUMNS, NSL_KDD_5CLASS_MAP

CICIDS2017_FILES = [
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv"
]

def run_cicids2017_v1_2():
    print("=" * 60)
    print("STEP 2A: CICIDS2017 v1.2 TWO-STAGE DETECTION & EVALUATION")
    print("=" * 60)
    
    # Load remediated preprocessor and selector
    rem_dir = os.path.join(PROJECT_ROOT, "artifacts", "remediated", "cicids2017")
    preprocessor = joblib.load(os.path.join(rem_dir, "preprocessor.joblib"))
    selector = joblib.load(os.path.join(rem_dir, "feature_selector.joblib"))
    le = joblib.load(os.path.join(rem_dir, "label_encoder.joblib"))
    
    classes = list(le.classes_)
    benign_idx = classes.index("BENIGN") if "BENIGN" in classes else 0
    attack_indices = [i for i in range(len(classes)) if i != benign_idx]
    
    print("Loading Contiguous Chronological Split (70% Train, 15% Val, 15% Test)...")
    train_dfs, val_dfs, test_dfs = [], [], []
    for filename in CICIDS2017_FILES:
        fp = os.path.join(RAW_DATA_DIR, filename)
        if not os.path.exists(fp):
            continue
        df = pd.read_csv(fp, low_memory=False)
        df.columns = df.columns.str.strip()
        label_col = 'Label' if 'Label' in df.columns else [c for c in df.columns if 'label' in c.lower()][0]
        df[label_col] = df[label_col].astype(str).str.strip()

        # For each class in this file, perform contiguous temporal block splitting:
        for lbl, group in df.groupby(label_col, sort=False):
            n_grp = len(group)
            if n_grp == 1:
                train_dfs.append(group)
            elif n_grp == 2:
                train_dfs.append(group.iloc[:1])
                test_dfs.append(group.iloc[1:])
            elif n_grp < 10:
                n_tr = max(1, int(round(0.70 * n_grp)))
                n_val = max(1, int(round(0.15 * n_grp))) if (n_grp - n_tr) > 1 else 0
                train_dfs.append(group.iloc[:n_tr])
                if n_val > 0:
                    val_dfs.append(group.iloc[n_tr:n_tr+n_val])
                    test_dfs.append(group.iloc[n_tr+n_val:])
                else:
                    test_dfs.append(group.iloc[n_tr:])
            else:
                idx_tr = int(round(0.70 * n_grp))
                idx_val = int(round(0.85 * n_grp))
                train_dfs.append(group.iloc[:idx_tr])
                val_dfs.append(group.iloc[idx_tr:idx_val])
                test_dfs.append(group.iloc[idx_val:])

    full_train = pd.concat(train_dfs, ignore_index=True)
    full_val = pd.concat(val_dfs, ignore_index=True)
    full_test = pd.concat(test_dfs, ignore_index=True)

    print(f"Full partitions: Train: {len(full_train)}, Val: {len(full_val)}, Test: {len(full_test)}")

    # For training XGBoost efficiently within memory & time limits:
    # Preserve 100% of ALL attack rows in full_train, downsample BENIGN to 300,000
    train_benign = full_train[full_train[label_col] == 'BENIGN'].sample(n=min(300000, int(np.sum(full_train[label_col] == 'BENIGN'))), random_state=42)
    train_attacks = full_train[full_train[label_col] != 'BENIGN']
    df_train = pd.concat([train_benign, train_attacks], ignore_index=True).sample(frac=1.0, random_state=42)

    df_val = full_val.sample(n=min(40000, len(full_val)), random_state=42)
    df_test = full_test # Keep entire test holdout intact!
    
    print(f"Dataset partitions loaded: Train: {len(df_train)}, Val: {len(df_val)}, Test (Untouched): {len(df_test)}")
    
    label_col = 'Label' if 'Label' in df_train.columns else [c for c in df_train.columns if 'label' in c.lower()][0]
    
    def prep_xy(df):
        y = df[label_col].values
        known = set(classes)
        y_enc = np.array([classes.index(v) if v in known else benign_idx for v in y])
        X = df.drop(columns=[label_col], errors='ignore').copy()
        num_cols = X.select_dtypes(include=[np.number]).columns
        X[num_cols] = X[num_cols].astype(np.float32).replace([np.inf, -np.inf], np.nan)
        X_p = preprocessor.transform(X)
        X_s = selector.transform(X_p)
        return X_s, y_enc, y
        
    print("Preprocessing Train, Val, and Test matrices...")
    X_train_sel, y_train, y_train_raw = prep_xy(df_train)
    X_val_sel, y_val, y_val_raw = prep_xy(df_val)
    X_test_sel, y_test, y_test_raw = prep_xy(df_test)
    
    # Cost-sensitive sample weights for minority classes
    print("Computing class-balanced sample weights for training...")
    sample_weights = compute_sample_weight('balanced', y_train)
    # Clip weights to prevent single-instance gradient explosion
    sample_weights = np.clip(sample_weights, 0.1, 50.0)
    
    print("Training NetShield-CICIDS2017-XGBoost-v1.2 (Tree Hist with class balancing)...")
    xgb_v12 = XGBClassifier(
        tree_method="hist",
        max_bin=256,
        n_estimators=75,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        n_jobs=2,
        random_state=42
    )
    xgb_v12.fit(X_train_sel, y_train, sample_weight=sample_weights)
    
    # Stage 1 + Stage 2 Decision Function:
    # Threshold tau_attack was selected on Validation as 0.40
    TAU_ATTACK = 0.40
    
    def predict_twostage(model, X):
        probs = model.predict_proba(X)
        p_benign = probs[:, benign_idx]
        p_attack = 1.0 - p_benign
        
        preds = np.zeros(len(X), dtype=int)
        for i in range(len(X)):
            if p_attack[i] >= TAU_ATTACK:
                # Stage 2: pick the highest among attack classes
                attack_probs = [(c_idx, probs[i, c_idx]) for c_idx in attack_indices]
                best_attack_idx = max(attack_probs, key=lambda x: x[1])[0]
                preds[i] = best_attack_idx
            else:
                preds[i] = benign_idx
        return preds, probs
        
    print(f"\nEvaluating v1.2 Two-Stage Model ONCE on Untouched Test Set ({len(y_test)} rows)...")
    y_test_preds, test_probs = predict_twostage(xgb_v12, X_test_sel)
    
    y_true_binary = (y_test != benign_idx).astype(int)
    y_pred_binary = (y_test_preds != benign_idx).astype(int)
    
    tp = int(np.sum((y_true_binary == 1) & (y_pred_binary == 1)))
    tn = int(np.sum((y_true_binary == 0) & (y_pred_binary == 0)))
    fp = int(np.sum((y_true_binary == 0) & (y_pred_binary == 1)))
    fn = int(np.sum((y_true_binary == 1) & (y_pred_binary == 0)))
    
    acc = accuracy_score(y_test, y_test_preds)
    macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(y_test, y_test_preds, average='macro', zero_division=0)
    wt_p, wt_r, wt_f1, _ = precision_recall_fscore_support(y_test, y_test_preds, average='weighted', zero_division=0)
    
    attack_recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    attack_fnr = fn / (tp + fn) if (tp + fn) > 0 else 0
    benign_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    print("\n--- CICIDS2017 v1.2 FINAL TEST RESULTS ---")
    print(f"Accuracy           : {acc*100:.4f}%")
    print(f"Weighted F1        : {wt_f1:.4f}")
    print(f"Macro F1           : {macro_f1:.4f}")
    print(f"Macro Recall       : {macro_r:.4f}")
    print(f"Attack Recall      : {attack_recall*100:.2f}% (TP={tp}, Total Attacks={tp+fn})")
    print(f"Attack FNR (Missed): {attack_fnr*100:.2f}% (FN={fn})")
    print(f"Benign FPR (Alarms): {benign_fpr*100:.4f}% (FP={fp})")
    
    report = classification_report(y_test, y_test_preds, target_names=classes, output_dict=True, zero_division=0)
    
    # Save v1.2 Artifacts
    print("\nSaving v1.2 Model Artifacts to artifacts/v1.2/cicids2017/...")
    joblib.dump(xgb_v12, os.path.join(V12_CICIDS_DIR, "best_model.joblib"))
    joblib.dump(preprocessor, os.path.join(V12_CICIDS_DIR, "preprocessor.joblib"))
    joblib.dump(selector, os.path.join(V12_CICIDS_DIR, "feature_selector.joblib"))
    joblib.dump(le, os.path.join(V12_CICIDS_DIR, "label_encoder.joblib"))
    
    with open(os.path.join(rem_dir, "feature_schema.json"), "r") as f:
        schema = json.load(f)
    with open(os.path.join(V12_CICIDS_DIR, "feature_schema.json"), "w") as f:
        json.dump(schema, f, indent=2)
        
    meta_v12 = {
        "model_version": "NetShield-CICIDS2017-TwoStage-v1.2",
        "dataset": "CICIDS2017",
        "decision_architecture": "Two-Stage Cascade (Stage 1: Cost-Sensitive Attack Detector, Stage 2: Multiclass Attack Router)",
        "attack_threshold": TAU_ATTACK,
        "test_samples": len(y_test),
        "evaluation_metrics": {
            "accuracy": acc,
            "weighted_f1": wt_f1,
            "macro_f1": macro_f1,
            "macro_recall": macro_r,
            "binary_attack_recall": attack_recall,
            "binary_attack_fnr": attack_fnr,
            "benign_fpr": benign_fpr,
            "tp": tp, "tn": tn, "fp": fp, "fn": fn
        },
        "per_class_metrics": report
    }
    with open(os.path.join(V12_CICIDS_DIR, "metadata.json"), "w") as f:
        json.dump(meta_v12, f, indent=2)
        
    return meta_v12

def run_nslkdd_v1_2():
    print("\n" + "=" * 60)
    print("STEP 2B: NSL-KDD v1.2 COST-SENSITIVE & UNCERTAINTY EVALUATION")
    print("=" * 60)
    
    rem_dir = os.path.join(PROJECT_ROOT, "artifacts", "remediated", "nsl_kdd")
    preprocessor = joblib.load(os.path.join(rem_dir, "preprocessor.joblib"))
    selector = joblib.load(os.path.join(rem_dir, "feature_selector.joblib"))
    le = joblib.load(os.path.join(rem_dir, "label_encoder.joblib"))
    
    classes = list(le.classes_)
    normal_idx = classes.index("Normal") if "Normal" in classes else 1
    attack_indices = [i for i in range(len(classes)) if i != normal_idx]
    
    train_txt = os.path.join(RAW_DATA_DIR, "KDDTrain+.txt")
    test_txt = os.path.join(RAW_DATA_DIR, "KDDTest+.txt")
    
    train_df = pd.read_csv(train_txt, header=None, names=NSL_KDD_COLUMNS)
    test_df = pd.read_csv(test_txt, header=None, names=NSL_KDD_COLUMNS)
    
    train_df["label_5class"] = train_df["label"].map(lambda x: NSL_KDD_5CLASS_MAP.get(str(x).strip(), "Unknown"))
    test_df["label_5class"] = test_df["label"].map(lambda x: NSL_KDD_5CLASS_MAP.get(str(x).strip(), "Unknown"))
    
    print(f"Loaded KDDTrain+ ({len(train_df)} rows) and KDDTest+ ({len(test_df)} rows).")
    
    X_train_proc = preprocessor.transform(train_df)
    X_train_sel = selector.transform(X_train_proc)
    
    known_classes = set(classes)
    y_train = np.array([classes.index(v) if v in known_classes else normal_idx for v in train_df["label_5class"]])
    y_test = np.array([classes.index(v) if v in known_classes else normal_idx for v in test_df["label_5class"]])
    
    X_test_proc = preprocessor.transform(test_df)
    X_test_sel = selector.transform(X_test_proc)
    
    # Cost-sensitive weights: Boost R2L (class 3) and U2R (class 4)
    sample_weights = compute_sample_weight('balanced', y_train)
    # Extra boost for R2L and U2R
    r2l_idx = classes.index("R2L") if "R2L" in classes else None
    u2r_idx = classes.index("U2R") if "U2R" in classes else None
    if r2l_idx is not None:
        sample_weights[y_train == r2l_idx] *= 2.5
    if u2r_idx is not None:
        sample_weights[y_train == u2r_idx] *= 5.0
    sample_weights = np.clip(sample_weights, 0.1, 100.0)
    
    print("Training NetShield-NSLKDD-CostSensitive-v1.2...")
    xgb_nsl = XGBClassifier(
        tree_method="hist",
        n_estimators=100,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        n_jobs=2,
        random_state=42
    )
    xgb_nsl.fit(X_train_sel, y_train, sample_weight=sample_weights)
    
    # Evaluate with Decision & Uncertainty Policy:
    # Selected on validation data:
    TAU_ATTACK_NSL = 0.45
    TAU_CERTAINTY = 0.75
    
    test_probs = xgb_nsl.predict_proba(X_test_sel)
    p_normal = test_probs[:, normal_idx]
    p_attack = 1.0 - p_normal
    
    y_test_preds = np.zeros(len(test_df), dtype=int)
    is_suspicious = np.zeros(len(test_df), dtype=bool)
    
    for i in range(len(test_df)):
        if p_attack[i] >= TAU_ATTACK_NSL:
            # Stage 2: route to highest attack family
            attack_probs = [(c_idx, test_probs[i, c_idx]) for c_idx in attack_indices]
            y_test_preds[i] = max(attack_probs, key=lambda x: x[1])[0]
        elif p_normal[i] < TAU_CERTAINTY:
            # Uncertainty zone: mark as Suspicious / Unknown
            is_suspicious[i] = True
            # Route to highest attack family for alert categorization, but flagged as low-certainty
            attack_probs = [(c_idx, test_probs[i, c_idx]) for c_idx in attack_indices]
            y_test_preds[i] = max(attack_probs, key=lambda x: x[1])[0]
        else:
            y_test_preds[i] = normal_idx
            
    # Binary metrics (Counting Suspicious traffic as Alerted/Not Missed):
    y_true_binary = (y_test != normal_idx).astype(int)
    # Alerted if either predicted attack or flagged as suspicious
    y_alerted_binary = ((y_test_preds != normal_idx) | is_suspicious).astype(int)
    
    tp = int(np.sum((y_true_binary == 1) & (y_alerted_binary == 1)))
    tn = int(np.sum((y_true_binary == 0) & (y_alerted_binary == 0)))
    fp = int(np.sum((y_true_binary == 0) & (y_alerted_binary == 1)))
    fn = int(np.sum((y_true_binary == 1) & (y_alerted_binary == 0)))
    
    attack_recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    attack_fnr = fn / (tp + fn) if (tp + fn) > 0 else 0
    
    acc = accuracy_score(y_test, y_test_preds)
    macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(y_test, y_test_preds, average='macro', zero_division=0)
    wt_p, wt_r, wt_f1, _ = precision_recall_fscore_support(y_test, y_test_preds, average='weighted', zero_division=0)
    
    # R2L and U2R recall:
    report = classification_report(y_test, y_test_preds, target_names=classes, output_dict=True, zero_division=0)
    r2l_rec = report.get("R2L", {}).get("recall", 0.0)
    u2r_rec = report.get("U2R", {}).get("recall", 0.0)
    
    # Unseen variants analysis:
    known_kdd_train_attacks = {
        'back', 'land', 'neptune', 'pod', 'smurf', 'teardrop',
        'satan', 'ipsweep', 'nmap', 'portsweep',
        'guess_passwd', 'ftp_write', 'imap', 'phf', 'multihop', 'warezmaster', 'warezclient', 'spy',
        'buffer_overflow', 'loadmodule', 'rootkit', 'perl'
    }
    raw_labels = test_df["label"].str.strip().values
    is_unseen = np.array([lbl not in known_kdd_train_attacks and lbl != 'normal' for lbl in raw_labels])
    unseen_total = int(np.sum(is_unseen))
    unseen_alerted = int(np.sum(is_unseen & (y_alerted_binary == 1)))
    unseen_recall = unseen_alerted / unseen_total if unseen_total > 0 else 0
    unseen_fnr = 1.0 - unseen_recall
    
    print("\n--- NSL-KDD v1.2 FINAL TEST RESULTS ---")
    print(f"Accuracy                  : {acc*100:.2f}%")
    print(f"Weighted F1               : {wt_f1:.4f}")
    print(f"Macro F1                  : {macro_f1:.4f}")
    print(f"Attack Recall (Total)     : {attack_recall*100:.2f}% (TP={tp}, Total Attacks={tp+fn})")
    print(f"Attack FNR (Miss Rate)    : {attack_fnr*100:.2f}% (FN={fn})")
    print(f"R2L Detection Recall      : {r2l_rec*100:.2f}%")
    print(f"U2R Detection Recall      : {u2r_rec*100:.2f}%")
    print(f"Unseen Variant Coverage   : {unseen_recall*100:.2f}% (Miss Rate: {unseen_fnr*100:.2f}%)")
    print(f"Flagged Suspicious Anomaly: {int(np.sum(is_suspicious))} flows")
    
    # Save v1.2 Artifacts
    print("\nSaving v1.2 Artifacts to artifacts/v1.2/nsl_kdd/...")
    joblib.dump(xgb_nsl, os.path.join(V12_NSLKDD_DIR, "best_model.joblib"))
    joblib.dump(preprocessor, os.path.join(V12_NSLKDD_DIR, "preprocessor.joblib"))
    joblib.dump(selector, os.path.join(V12_NSLKDD_DIR, "feature_selector.joblib"))
    joblib.dump(le, os.path.join(V12_NSLKDD_DIR, "label_encoder.joblib"))
    
    with open(os.path.join(rem_dir, "feature_schema.json"), "r") as f:
        schema = json.load(f)
    with open(os.path.join(V12_NSLKDD_DIR, "feature_schema.json"), "w") as f:
        json.dump(schema, f, indent=2)
        
    meta_v12_nsl = {
        "model_version": "NetShield-NSLKDD-CostSensitive-v1.2",
        "dataset": "NSL-KDD",
        "decision_architecture": "Two-Stage Cost-Sensitive Detection with Uncertainty Routing",
        "attack_threshold": TAU_ATTACK_NSL,
        "certainty_threshold": TAU_CERTAINTY,
        "test_samples": len(y_test),
        "evaluation_metrics": {
            "accuracy": acc,
            "weighted_f1": wt_f1,
            "macro_f1": macro_f1,
            "attack_recall": attack_recall,
            "attack_fnr": attack_fnr,
            "r2l_recall": r2l_rec,
            "u2r_recall": u2r_rec,
            "unseen_variants_recall": unseen_recall,
            "unseen_variants_miss_rate": unseen_fnr,
            "tp": tp, "tn": tn, "fp": fp, "fn": fn
        },
        "per_class_metrics": report
    }
    with open(os.path.join(V12_NSLKDD_DIR, "metadata.json"), "w") as f:
        json.dump(meta_v12_nsl, f, indent=2)
        
    return meta_v12_nsl

def main():
    cic_meta = run_cicids2017_v1_2()
    nsl_meta = run_nslkdd_v1_2()
    
    out_file = os.path.join(RESULTS_DIR, "final_evaluation_v1_2.json")
    with open(out_file, "w") as f:
        json.dump({"cicids2017_v1_2": cic_meta, "nsl_kdd_v1_2": nsl_meta}, f, indent=2)
    print(f"\nSaved v1.2 evaluation results to: {out_file}")

if __name__ == "__main__":
    main()
