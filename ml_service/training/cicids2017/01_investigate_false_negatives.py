import os
import sys
import json
import numpy as np
import pandas as pd
import joblib

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

def analyze_cicids2017_validation_fn():
    print("=" * 60)
    print("STEP 1A: CICIDS2017 VALIDATION FALSE NEGATIVE INVESTIGATION")
    print("=" * 60)
    
    rem_dir = os.path.join(PROJECT_ROOT, "artifacts", "remediated", "cicids2017")
    model = joblib.load(os.path.join(rem_dir, "best_model.joblib"))
    preprocessor = joblib.load(os.path.join(rem_dir, "preprocessor.joblib"))
    selector = joblib.load(os.path.join(rem_dir, "feature_selector.joblib"))
    le = joblib.load(os.path.join(rem_dir, "label_encoder.joblib"))
    
    classes = list(le.classes_)
    benign_idx = classes.index("BENIGN") if "BENIGN" in classes else 0
    
    print("Loading Validation Partition (contiguous 70% to 85% block per PCAP)...")
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
        
        # Take up to 5,000 samples per capture for fast thorough profiling
        if len(val_slice) > 5000:
            sample_df = val_slice.sample(n=5000, random_state=42)
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
    
    probs = model.predict_proba(X_val_sel)
    preds = np.argmax(probs, axis=1)
    
    # Ground truth binary
    is_attack_true = (y_val_raw != "BENIGN")
    is_attack_pred = (preds != benign_idx)
    
    # False negatives: true attack, but predicted BENIGN
    fn_mask = is_attack_true & (~is_attack_pred)
    total_attacks = int(np.sum(is_attack_true))
    total_fn = int(np.sum(fn_mask))
    
    print(f"\nValidation Attacks Total: {total_attacks}")
    print(f"Validation False Negatives (Missed Attacks): {total_fn} ({total_fn/total_attacks*100:.2f}%)")
    
    # Analyze breakdown by true attack label
    fn_by_label = {}
    attack_labels = sorted(list(set(y_val_raw[is_attack_true])))
    
    for lbl in attack_labels:
        lbl_mask = (y_val_raw == lbl)
        support = int(np.sum(lbl_mask))
        fn_count = int(np.sum(lbl_mask & fn_mask))
        recall = (support - fn_count) / support if support > 0 else 0
        pct_of_all_fn = (fn_count / total_fn * 100) if total_fn > 0 else 0
        
        # Probabilities for missed samples
        if fn_count > 0:
            fn_probs = probs[lbl_mask & fn_mask]
            # P(BENIGN) for these missed attacks
            p_benign_mean = float(np.mean(fn_probs[:, benign_idx]))
            # P(Attack) = 1 - P(BENIGN)
            p_attack_mean = float(np.mean(1.0 - fn_probs[:, benign_idx]))
            p_attack_median = float(np.median(1.0 - fn_probs[:, benign_idx]))
        else:
            p_benign_mean, p_attack_mean, p_attack_median = 0.0, 0.0, 0.0
            
        fn_by_label[lbl] = {
            "support": support,
            "false_negatives": fn_count,
            "recall": round(recall, 4),
            "pct_of_total_fn": round(pct_of_all_fn, 2),
            "p_benign_mean_when_missed": round(p_benign_mean, 4),
            "p_attack_mean_when_missed": round(p_attack_mean, 4),
            "p_attack_median_when_missed": round(p_attack_median, 4)
        }
        print(f"  - {lbl:30s} | Support: {support:5d} | FN: {fn_count:5d} ({pct_of_all_fn:5.1f}% of FN) | Recall: {recall*100:5.1f}% | Avg P(Attack) in FN: {p_attack_mean:.3f}")
        
    # Distribution of P(Attack) among false negatives:
    fn_p_attack = 1.0 - probs[fn_mask, benign_idx]
    p_attack_bands = {
        ">= 0.40": int(np.sum(fn_p_attack >= 0.40)),
        "0.30 - 0.40": int(np.sum((fn_p_attack >= 0.30) & (fn_p_attack < 0.40))),
        "0.20 - 0.30": int(np.sum((fn_p_attack >= 0.20) & (fn_p_attack < 0.30))),
        "0.10 - 0.20": int(np.sum((fn_p_attack >= 0.10) & (fn_p_attack < 0.20))),
        "< 0.10": int(np.sum(fn_p_attack < 0.10))
    }
    print("\nP(Attack) Distribution Among Missed Attacks:")
    for band, count in p_attack_bands.items():
        print(f"  - P(Attack) in {band:12s}: {count:5d} ({count/total_fn*100:.1f}%)")
        
    return {
        "dataset": "CICIDS2017",
        "total_attacks": total_attacks,
        "total_fn": total_fn,
        "overall_fnr": round(total_fn / total_attacks, 4),
        "breakdown": fn_by_label,
        "p_attack_distribution_in_fn": p_attack_bands
    }

def analyze_nslkdd_validation_fn():
    print("\n" + "=" * 60)
    print("STEP 1B: NSL-KDD VALIDATION FALSE NEGATIVE INVESTIGATION")
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
    print(f"Validation split created: {len(val_df)} rows from KDDTrain+.")
    
    X_val_proc = preprocessor.transform(val_df)
    X_val_sel = selector.transform(X_val_proc)
    
    probs = model.predict_proba(X_val_sel)
    preds = np.argmax(probs, axis=1)
    
    y_val_5class = val_df["label_5class"].values
    is_attack_true = (y_val_5class != "Normal")
    is_attack_pred = (preds != normal_idx)
    
    fn_mask = is_attack_true & (~is_attack_pred)
    total_attacks = int(np.sum(is_attack_true))
    total_fn = int(np.sum(fn_mask))
    
    print(f"\nValidation Attacks Total: {total_attacks}")
    print(f"Validation False Negatives (Missed Attacks): {total_fn} ({total_fn/total_attacks*100:.2f}%)")
    
    fn_by_family = {}
    families = ["DoS", "Probe", "R2L", "U2R"]
    for fam in families:
        fam_mask = (y_val_5class == fam)
        support = int(np.sum(fam_mask))
        fn_count = int(np.sum(fam_mask & fn_mask))
        recall = (support - fn_count) / support if support > 0 else 0
        pct_of_all_fn = (fn_count / total_fn * 100) if total_fn > 0 else 0
        
        if fn_count > 0:
            fn_probs = probs[fam_mask & fn_mask]
            p_normal_mean = float(np.mean(fn_probs[:, normal_idx]))
            p_attack_mean = float(np.mean(1.0 - fn_probs[:, normal_idx]))
        else:
            p_normal_mean, p_attack_mean = 0.0, 0.0
            
        fn_by_family[fam] = {
            "support": support,
            "false_negatives": fn_count,
            "recall": round(recall, 4),
            "pct_of_total_fn": round(pct_of_all_fn, 2),
            "p_attack_mean_when_missed": round(p_attack_mean, 4)
        }
        print(f"  - {fam:10s} | Support: {support:5d} | FN: {fn_count:5d} ({pct_of_all_fn:5.1f}% of FN) | Recall: {recall*100:5.1f}% | Avg P(Attack): {p_attack_mean:.3f}")
        
    fn_p_attack = 1.0 - probs[fn_mask, normal_idx]
    p_attack_bands = {
        ">= 0.40": int(np.sum(fn_p_attack >= 0.40)),
        "0.30 - 0.40": int(np.sum((fn_p_attack >= 0.30) & (fn_p_attack < 0.40))),
        "0.20 - 0.30": int(np.sum((fn_p_attack >= 0.20) & (fn_p_attack < 0.30))),
        "0.10 - 0.20": int(np.sum((fn_p_attack >= 0.10) & (fn_p_attack < 0.20))),
        "< 0.10": int(np.sum(fn_p_attack < 0.10))
    }
    print("\nP(Attack) Distribution Among Missed Attacks:")
    for band, count in p_attack_bands.items():
        print(f"  - P(Attack) in {band:12s}: {count:5d} ({count/total_fn*100:.1f}%)")
        
    return {
        "dataset": "NSL-KDD",
        "total_attacks": total_attacks,
        "total_fn": total_fn,
        "overall_fnr": round(total_fn / total_attacks, 4),
        "breakdown": fn_by_family,
        "p_attack_distribution_in_fn": p_attack_bands
    }

def main():
    cic_results = analyze_cicids2017_validation_fn()
    nsl_results = analyze_nslkdd_validation_fn()
    
    out_file = os.path.join(RESULTS_DIR, "false_negative_analysis.json")
    with open(out_file, "w") as f:
        json.dump({"cicids2017": cic_results, "nsl_kdd": nsl_results}, f, indent=2)
    print(f"\nSaved false negative analysis to: {out_file}")

if __name__ == "__main__":
    main()
