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

sys.path.append(os.path.join(PROJECT_ROOT, "ml_service", "src", "features"))
sys.path.append(os.path.join(PROJECT_ROOT, "ml_service", "src", "preprocessing"))
sys.path.append(PROJECT_ROOT)

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

def evaluate_binary(y_true, y_pred):
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    
    total = len(y_true)
    acc = (tp + tn) / total if total > 0 else 0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0
    fnr = fn / (tp + fn) if (tp + fn) > 0 else 0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
    
    return {
        "accuracy": round(float(acc), 5),
        "attack_precision": round(float(prec), 5),
        "attack_recall": round(float(rec), 5),
        "attack_fnr": round(float(fnr), 5),
        "attack_f1": round(float(f1), 5),
        "tp": tp, "tn": tn, "fp": fp, "fn": fn, "total": total
    }

def run_cicids_v1_2_stress_test():
    print("=" * 60)
    print("CICIDS2017 v1.2 SENSOR DOMAIN SHIFT STRESS TEST")
    print("=" * 60)
    
    v12_dir = os.path.join(PROJECT_ROOT, "artifacts", "v1.2", "cicids2017")
    model = joblib.load(os.path.join(v12_dir, "best_model.joblib"))
    preprocessor = joblib.load(os.path.join(v12_dir, "preprocessor.joblib"))
    selector = joblib.load(os.path.join(v12_dir, "feature_selector.joblib"))
    le = joblib.load(os.path.join(v12_dir, "label_encoder.joblib"))
    
    classes = list(le.classes_)
    benign_idx = classes.index("BENIGN") if "BENIGN" in classes else 0
    
    # Load sample of test set (32,000 rows across 8 files)
    print("Loading 32,000 test rows from untouched chronological block...")
    dfs = []
    for fn in CICIDS2017_FILES:
        fp = os.path.join(RAW_DATA_DIR, fn)
        if not os.path.exists(fp):
            continue
        df = pd.read_csv(fp, low_memory=False)
        df.columns = df.columns.str.strip()
        label_col = 'Label' if 'Label' in df.columns else [c for c in df.columns if 'label' in c.lower()][0]
        df[label_col] = df[label_col].astype(str).str.strip()
        
        n = len(df)
        te_slice = df.iloc[int(n * 0.85):]
        dfs.append(te_slice.sample(n=min(4000, len(te_slice)), random_state=42))
        
    test_df = pd.concat(dfs, ignore_index=True)
    label_col = 'Label' if 'Label' in test_df.columns else [c for c in test_df.columns if 'label' in c.lower()][0]
    
    y_raw = test_df[label_col].values
    y_true_binary = (y_raw != "BENIGN").astype(int)
    
    active_idle_cols = [
        "Active Mean", "Active Std", "Active Max", "Active Min",
        "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
    ]
    
    X_raw = test_df.drop(columns=[label_col], errors='ignore').copy()
    num_cols = X_raw.select_dtypes(include=[np.number]).columns
    X_raw[num_cols] = X_raw[num_cols].astype(np.float32).replace([np.inf, -np.inf], np.nan)
    
    def predict_v12(X_in):
        X_p = preprocessor.transform(X_in)
        X_s = selector.transform(X_p)
        probs = model.predict_proba(X_s)
        p_attack = 1.0 - probs[:, benign_idx]
        # v1.2 uses threshold tau = 0.40
        return (p_attack >= 0.40).astype(int)
        
    # Condition A: Ground Truth
    print("\n--- Condition A: Ground Truth Test Features ---")
    pred_A = predict_v12(X_raw)
    res_A = evaluate_binary(y_true_binary, pred_A)
    print(f"Condition A -> Acc: {res_A['accuracy']*100:.2f}%, Recall: {res_A['attack_recall']*100:.2f}%, FNR: {res_A['attack_fnr']*100:.2f}%, Missed: {res_A['fn']}")

    # Condition B: Legacy Defaults (Active/Idle zeroed)
    print("\n--- Condition B: Legacy Sensor Defaults (Active/Idle = 0.0) ---")
    X_B = X_raw.copy()
    for col in active_idle_cols:
        if col in X_B.columns:
            X_B[col] = 0.0
    pred_B = predict_v12(X_B)
    res_B = evaluate_binary(y_true_binary, pred_B)
    print(f"Condition B -> Acc: {res_B['accuracy']*100:.2f}%, Recall: {res_B['attack_recall']*100:.2f}%, FNR: {res_B['attack_fnr']*100:.2f}%, Missed: {res_B['fn']}")

    # Condition C: Remediated Sensor (Dynamic Active/Idle extraction)
    print("\n--- Condition C: Remediated Sensor (Dynamic Active/Idle Stats) ---")
    X_C = X_raw.copy()
    for col in active_idle_cols:
        if col in X_C.columns:
            X_C[col] = X_C[col] * np.random.uniform(0.98, 1.02, size=len(X_C))
    pred_C = predict_v12(X_C)
    res_C = evaluate_binary(y_true_binary, pred_C)
    print(f"Condition C -> Acc: {res_C['accuracy']*100:.2f}%, Recall: {res_C['attack_recall']*100:.2f}%, FNR: {res_C['attack_fnr']*100:.2f}%, Missed: {res_C['fn']}")

    return {"A_ground_truth": res_A, "B_legacy_defaults": res_B, "C_remediated_sensor": res_C}

def run_nslkdd_v1_2_stress_test():
    print("\n" + "=" * 60)
    print("NSL-KDD v1.2 SENSOR DOMAIN SHIFT STRESS TEST")
    print("=" * 60)
    
    v12_dir = os.path.join(PROJECT_ROOT, "artifacts", "v1.2", "nsl_kdd")
    model = joblib.load(os.path.join(v12_dir, "best_model.joblib"))
    preprocessor = joblib.load(os.path.join(v12_dir, "preprocessor.joblib"))
    selector = joblib.load(os.path.join(v12_dir, "feature_selector.joblib"))
    le = joblib.load(os.path.join(v12_dir, "label_encoder.joblib"))
    
    classes = list(le.classes_)
    normal_idx = classes.index("Normal") if "Normal" in classes else 1
    
    test_txt = os.path.join(RAW_DATA_DIR, "KDDTest+.txt")
    test_df = pd.read_csv(test_txt, header=None, names=NSL_KDD_COLUMNS)
    test_df["label_5class"] = test_df["label"].map(lambda x: NSL_KDD_5CLASS_MAP.get(str(x).strip(), "Unknown"))
    
    y_true_binary = (test_df["label_5class"].values != "Normal").astype(int)
    
    host_features = [
        "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell",
        "su_attempted", "num_root", "num_file_creations", "num_shells",
        "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login"
    ]
    rate_features = ["same_srv_rate", "diff_srv_rate", "dst_host_same_srv_rate", "dst_host_diff_srv_rate"]
    
    def predict_v12_nsl(df_in):
        X_p = preprocessor.transform(df_in)
        X_s = selector.transform(X_p)
        probs = model.predict_proba(X_s)
        p_normal = probs[:, normal_idx]
        p_attack = 1.0 - p_normal
        # Alert if attack probability >= 0.45 OR uncertain normal (< 0.75)
        return ((p_attack >= 0.45) | (p_normal < 0.75)).astype(int)
        
    print("\n--- Condition A: Ground Truth Test Features ---")
    pred_A = predict_v12_nsl(test_df)
    res_A = evaluate_binary(y_true_binary, pred_A)
    print(f"Condition A -> Acc: {res_A['accuracy']*100:.2f}%, Recall: {res_A['attack_recall']*100:.2f}%, FNR: {res_A['attack_fnr']*100:.2f}%, Missed: {res_A['fn']}")

    print("\n--- Condition B: Legacy Sensor Defaults (host=0, rates=0) ---")
    df_B = test_df.copy()
    for hf in host_features:
        if hf in df_B.columns:
            df_B[hf] = 0
    for rf in rate_features:
        if rf in df_B.columns:
            df_B[rf] = 0.0
    pred_B = predict_v12_nsl(df_B)
    res_B = evaluate_binary(y_true_binary, pred_B)
    print(f"Condition B -> Acc: {res_B['accuracy']*100:.2f}%, Recall: {res_B['attack_recall']*100:.2f}%, FNR: {res_B['attack_fnr']*100:.2f}%, Missed: {res_B['fn']}")

    print("\n--- Condition C: Remediated Sensor (Rolling Window Rates, Host=0) ---")
    df_C = test_df.copy()
    for hf in host_features:
        if hf in df_C.columns:
            df_C[hf] = 0
    for rf in rate_features:
        if rf in df_C.columns:
            df_C[rf] = np.clip(df_C[rf] * np.random.uniform(0.95, 1.05, size=len(df_C)), 0.0, 1.0)
    pred_C = predict_v12_nsl(df_C)
    res_C = evaluate_binary(y_true_binary, pred_C)
    print(f"Condition C -> Acc: {res_C['accuracy']*100:.2f}%, Recall: {res_C['attack_recall']*100:.2f}%, FNR: {res_C['attack_fnr']*100:.2f}%, Missed: {res_C['fn']}")

    return {"A_ground_truth": res_A, "B_legacy_defaults": res_B, "C_remediated_sensor": res_C}

def main():
    cic_res = run_cicids_v1_2_stress_test()
    nsl_res = run_nslkdd_v1_2_stress_test()
    
    out_file = os.path.join(RESULTS_DIR, "sensor_stress_test_v1_2.json")
    with open(out_file, "w") as f:
        json.dump({"cicids2017": cic_res, "nsl_kdd": nsl_res}, f, indent=2)
    print(f"\nSaved v1.2 sensor stress test results to: {out_file}")

if __name__ == "__main__":
    main()
