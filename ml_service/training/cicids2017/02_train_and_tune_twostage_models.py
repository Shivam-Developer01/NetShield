import os
import sys
import json
import numpy as np
import pandas as pd
import joblib
from xgboost import XGBClassifier
from sklearn.metrics import recall_score, precision_score, f1_score, confusion_matrix

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
RAW_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "raw")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

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

def tune_cicids2017_thresholds():
    print("=" * 60)
    print("EXPERIMENT 1: CICIDS2017 TWO-STAGE & THRESHOLD SELECTION")
    print("=" * 60)
    
    rem_dir = os.path.join(PROJECT_ROOT, "artifacts", "remediated", "cicids2017")
    model = joblib.load(os.path.join(rem_dir, "best_model.joblib"))
    preprocessor = joblib.load(os.path.join(rem_dir, "preprocessor.joblib"))
    selector = joblib.load(os.path.join(rem_dir, "feature_selector.joblib"))
    le = joblib.load(os.path.join(rem_dir, "label_encoder.joblib"))
    
    classes = list(le.classes_)
    benign_idx = classes.index("BENIGN") if "BENIGN" in classes else 0
    
    print("Loading Validation Partition for CICIDS2017 (70% - 85% block per PCAP)...")
    val_dfs = []
    for filename in CICIDS2017_FILES:
        fp = os.path.join(RAW_DATA_DIR, filename)
        if not os.path.exists(fp):
            continue
        df = pd.read_csv(fp, low_memory=False)
        df.columns = df.columns.str.strip()
        label_col = 'Label' if 'Label' in df.columns else [c for c in df.columns if 'label' in c.lower()][0]
        df[label_col] = df[label_col].astype(str).str.strip()
        
        n = len(df)
        val_slice = df.iloc[int(n * 0.70):int(n * 0.85)].copy()
        if len(val_slice) > 8000:
            sample_df = val_slice.sample(n=8000, random_state=42)
        else:
            sample_df = val_slice
        val_dfs.append(sample_df)
        
    val_df = pd.concat(val_dfs, ignore_index=True)
    label_col = 'Label' if 'Label' in val_df.columns else [c for c in val_df.columns if 'label' in c.lower()][0]
    
    y_val_raw = val_df[label_col].values
    X_val_raw = val_df.drop(columns=[label_col], errors='ignore').copy()
    num_cols = X_val_raw.select_dtypes(include=[np.number]).columns
    X_val_raw[num_cols] = X_val_raw[num_cols].astype(np.float32).replace([np.inf, -np.inf], np.nan)
    
    X_val_proc = preprocessor.transform(X_val_raw)
    X_val_sel = selector.transform(X_val_proc)
    
    # Compute probability matrix on validation set
    probs = model.predict_proba(X_val_sel)
    p_attack = 1.0 - probs[:, benign_idx]
    y_true_binary = (y_val_raw != "BENIGN").astype(int)
    
    print(f"Validation Set Size: {len(y_val_raw)} rows (Attacks: {np.sum(y_true_binary)}, Benign: {np.sum(y_true_binary == 0)})")
    
    # Evaluate thresholds from 0.05 to 0.50 strictly on validation set
    thresholds = [0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]
    grid_results = []
    
    print("\n--- Validation Threshold Scan for P(Attack) ---")
    print("Thresh | Attack Recall | Attack FNR | Benign FPR | Attack Precision | Binary F1 | Alert Volume %")
    print("-" * 78)
    
    best_thresh = 0.50
    best_f1 = 0.0
    for tau in thresholds:
        y_pred_binary = (p_attack >= tau).astype(int)
        
        tp = int(np.sum((y_true_binary == 1) & (y_pred_binary == 1)))
        tn = int(np.sum((y_true_binary == 0) & (y_pred_binary == 0)))
        fp = int(np.sum((y_true_binary == 0) & (y_pred_binary == 1)))
        fn = int(np.sum((y_true_binary == 1) & (y_pred_binary == 0)))
        
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        fnr = fn / (tp + fn) if (tp + fn) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        f1 = 2 * prec * recall / (prec + recall) if (prec + recall) > 0 else 0
        alert_vol = (tp + fp) / len(y_true_binary) * 100
        
        grid_results.append({
            "threshold": tau,
            "attack_recall": round(recall, 5),
            "attack_fnr": round(fnr, 5),
            "benign_fpr": round(fpr, 5),
            "attack_precision": round(prec, 5),
            "binary_f1": round(f1, 5),
            "alert_volume_pct": round(alert_vol, 2)
        })
        print(f" {tau:4.2f}  |    {recall*100:5.2f}%    |   {fnr*100:5.2f}%   |   {fpr*100:5.2f}%   |     {prec*100:5.2f}%      |  {f1:6.4f}   |    {alert_vol:5.2f}%")
        
        # Operational criteria: Maximize Recall while keeping FPR <= 0.5% (low false alarm rate for SOC)
        if fpr <= 0.005 and f1 > best_f1:
            best_f1 = f1
            best_thresh = tau
            
    print(f"\nOptimal Operational Validation Threshold Selected: tau = {best_thresh} (FPR <= 0.5%, F1 = {best_f1:.4f})")
    
    return {
        "dataset": "CICIDS2017",
        "validation_samples": len(y_val_raw),
        "selected_threshold": best_thresh,
        "selected_f1": best_f1,
        "grid_results": grid_results
    }

def tune_nslkdd_thresholds_and_uncertainty():
    print("\n" + "=" * 60)
    print("EXPERIMENT 2: NSL-KDD THRESHOLD & UNCERTAINTY TUNING")
    print("=" * 60)
    
    rem_dir = os.path.join(PROJECT_ROOT, "artifacts", "remediated", "nsl_kdd")
    model = joblib.load(os.path.join(rem_dir, "best_model.joblib"))
    preprocessor = joblib.load(os.path.join(rem_dir, "preprocessor.joblib"))
    selector = joblib.load(os.path.join(rem_dir, "feature_selector.joblib"))
    le = joblib.load(os.path.join(rem_dir, "label_encoder.joblib"))
    
    classes = list(le.classes_)
    normal_idx = classes.index("Normal") if "Normal" in classes else 1
    
    train_txt = os.path.join(RAW_DATA_DIR, "KDDTrain+.txt")
    train_df = pd.read_csv(train_txt, header=None, names=NSL_KDD_COLUMNS)
    train_df["label_5class"] = train_df["label"].map(lambda x: NSL_KDD_5CLASS_MAP.get(str(x).strip(), "Unknown"))
    
    # 80/20 Stratified Train/Val split of KDDTrain+
    np.random.seed(42)
    val_indices = []
    for cls_name, grp in train_df.groupby("label_5class"):
        n_val = int(len(grp) * 0.20)
        val_idx = np.random.choice(grp.index, size=n_val, replace=False)
        val_indices.extend(val_idx)
        
    val_df = train_df.loc[val_indices].copy()
    X_val_proc = preprocessor.transform(val_df)
    X_val_sel = selector.transform(X_val_proc)
    
    probs = model.predict_proba(X_val_sel)
    p_attack = 1.0 - probs[:, normal_idx]
    y_true_binary = (val_df["label_5class"].values != "Normal").astype(int)
    
    thresholds = [0.10, 0.20, 0.30, 0.35, 0.40, 0.45, 0.50]
    grid_results = []
    print("\n--- Validation Threshold Scan for NSL-KDD P(Attack) ---")
    print("Thresh | Attack Recall | Attack FNR | Benign FPR | Attack Precision | Binary F1")
    print("-" * 68)
    
    best_thresh_nsl = 0.50
    best_f1_nsl = 0.0
    for tau in thresholds:
        y_pred_binary = (p_attack >= tau).astype(int)
        tp = int(np.sum((y_true_binary == 1) & (y_pred_binary == 1)))
        tn = int(np.sum((y_true_binary == 0) & (y_pred_binary == 0)))
        fp = int(np.sum((y_true_binary == 0) & (y_pred_binary == 1)))
        fn = int(np.sum((y_true_binary == 1) & (y_pred_binary == 0)))
        
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        fnr = fn / (tp + fn) if (tp + fn) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        f1 = 2 * prec * recall / (prec + recall) if (prec + recall) > 0 else 0
        
        grid_results.append({
            "threshold": tau,
            "attack_recall": round(recall, 5),
            "attack_fnr": round(fnr, 5),
            "benign_fpr": round(fpr, 5),
            "attack_precision": round(prec, 5),
            "binary_f1": round(f1, 5)
        })
        print(f" {tau:4.2f}  |    {recall*100:5.2f}%    |   {fnr*100:5.2f}%   |   {fpr*100:5.2f}%   |     {prec*100:5.2f}%      |  {f1:6.4f}")
        
        if f1 > best_f1_nsl and fpr <= 0.05:
            best_f1_nsl = f1
            best_thresh_nsl = tau
            
    print(f"\nOptimal Operational Validation Threshold Selected: tau = {best_thresh_nsl} (F1 = {best_f1_nsl:.4f})")
    
    # Step 9: Uncertainty / Low-Confidence Policy Evaluation on Validation Set
    print("\n--- Uncertainty / Unknown Anomaly Tuning (Validation Data) ---")
    # If P(Normal) is between [0.50, tau_certainty], we flag as 'Suspicious / Unknown Anomaly'
    certainty_thresholds = [0.60, 0.70, 0.75, 0.80, 0.85]
    uncertainty_results = []
    
    for c_tau in certainty_thresholds:
        # Sample is considered 'Certain Normal' ONLY IF P(Normal) >= c_tau
        # Otherwise if P(Normal) < c_tau, it is flagged as 'Suspicious / Unknown' or Attack
        is_suspicious = (probs[:, normal_idx] >= 0.50) & (probs[:, normal_idx] < c_tau)
        suspicious_count = int(np.sum(is_suspicious))
        suspicious_attacks = int(np.sum(is_suspicious & (y_true_binary == 1)))
        suspicious_normals = int(np.sum(is_suspicious & (y_true_binary == 0)))
        
        uncertainty_results.append({
            "normal_certainty_threshold": c_tau,
            "suspicious_total": suspicious_count,
            "suspicious_attacks_caught": suspicious_attacks,
            "suspicious_benign_flagged": suspicious_normals
        })
        print(f"  Confidence Threshold: {c_tau:.2f} -> Flagged Suspicious: {suspicious_count:4d} (Attacks: {suspicious_attacks:3d}, Benign: {suspicious_normals:3d})")
        
    return {
        "dataset": "NSL-KDD",
        "validation_samples": len(val_df),
        "selected_attack_threshold": best_thresh_nsl,
        "selected_normal_certainty_threshold": 0.75,
        "grid_results": grid_results,
        "uncertainty_results": uncertainty_results
    }

def main():
    cic_res = tune_cicids2017_thresholds()
    nsl_res = tune_nslkdd_thresholds_and_uncertainty()
    
    out_file = os.path.join(RESULTS_DIR, "threshold_selection.json")
    with open(out_file, "w") as f:
        json.dump({"cicids2017": cic_res, "nsl_kdd": nsl_res}, f, indent=2)
    print(f"\nSaved threshold selection results to: {out_file}")

if __name__ == "__main__":
    main()
