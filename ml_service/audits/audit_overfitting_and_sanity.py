import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_recall_fscore_support

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PROCESSED_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "processed")
ARTIFACTS_DIR = os.path.join(PROJECT_ROOT, "artifacts")
sys.path.append(os.path.join(PROJECT_ROOT, "ml_service", "src", "features"))

def audit_overfitting():
    print("=" * 60)
    print("PHASE I: OVERFITTING / GENERALIZATION AUDIT")
    print("=" * 60)
    
    # NSL-KDD Train vs Test
    nsl_model = joblib.load(os.path.join(ARTIFACTS_DIR, "production", "nsl_kdd", "best_model.joblib"))
    nsl_train_data = np.load(os.path.join(PROCESSED_DATA_DIR, "nsl_kdd", "train_reduced.npz"))
    nsl_test_data = np.load(os.path.join(PROCESSED_DATA_DIR, "nsl_kdd", "test_reduced.npz"))
    
    X_tr_nsl, y_tr_nsl = nsl_train_data['X'], nsl_train_data['y_5class']
    X_te_nsl, y_te_nsl = nsl_test_data['X'], nsl_test_data['y_5class']
    
    y_tr_pred_nsl = nsl_model.predict(X_tr_nsl)
    y_te_pred_nsl = nsl_model.predict(X_te_nsl)
    
    tr_acc_nsl = accuracy_score(y_tr_nsl, y_tr_pred_nsl)
    te_acc_nsl = accuracy_score(y_te_nsl, y_te_pred_nsl)
    tr_f1_w_nsl = f1_score(y_tr_nsl, y_tr_pred_nsl, average='weighted', zero_division=0)
    te_f1_w_nsl = f1_score(y_te_nsl, y_te_pred_nsl, average='weighted', zero_division=0)
    tr_f1_m_nsl = f1_score(y_tr_nsl, y_tr_pred_nsl, average='macro', zero_division=0)
    te_f1_m_nsl = f1_score(y_te_nsl, y_te_pred_nsl, average='macro', zero_division=0)
    
    print(f"NSL-KDD Train Accuracy: {tr_acc_nsl:.4f} ({tr_acc_nsl*100:.2f}%)")
    print(f"NSL-KDD Test Accuracy : {te_acc_nsl:.4f} ({te_acc_nsl*100:.2f}%)")
    print(f"NSL-KDD Generalization Gap (Acc): {tr_acc_nsl - te_acc_nsl:.4f} ({(tr_acc_nsl - te_acc_nsl)*100:.2f}%)")
    print(f"NSL-KDD Train Weighted F1: {tr_f1_w_nsl:.4f} | Test Weighted F1: {te_f1_w_nsl:.4f}")
    print(f"NSL-KDD Train Macro F1   : {tr_f1_m_nsl:.4f} | Test Macro F1   : {te_f1_m_nsl:.4f}")
    
    # CICIDS2017 Train vs Test (on sample of train)
    cic_model = joblib.load(os.path.join(ARTIFACTS_DIR, "production", "cicids2017", "best_model.joblib"))
    cic_train_data = np.load(os.path.join(PROCESSED_DATA_DIR, "cicids2017", "train_reduced.npz"))
    cic_test_data = np.load(os.path.join(PROCESSED_DATA_DIR, "cicids2017", "test_reduced.npz"))
    
    X_tr_cic, y_tr_cic = cic_train_data['X'], cic_train_data['y']
    X_te_cic, y_te_cic = cic_test_data['X'], cic_test_data['y']
    
    # Predict on 100k train sample
    np.random.seed(42)
    idx_sample = np.random.choice(len(X_tr_cic), 100000, replace=False)
    y_tr_pred_cic = cic_model.predict(X_tr_cic[idx_sample])
    y_te_pred_cic = cic_model.predict(X_te_cic)
    
    tr_acc_cic = accuracy_score(y_tr_cic[idx_sample], y_tr_pred_cic)
    te_acc_cic = accuracy_score(y_te_cic, y_te_pred_cic)
    tr_f1_w_cic = f1_score(y_tr_cic[idx_sample], y_tr_pred_cic, average='weighted', zero_division=0)
    te_f1_w_cic = f1_score(y_te_cic, y_te_pred_cic, average='weighted', zero_division=0)
    tr_f1_m_cic = f1_score(y_tr_cic[idx_sample], y_tr_pred_cic, average='macro', zero_division=0)
    te_f1_m_cic = f1_score(y_te_cic, y_te_pred_cic, average='macro', zero_division=0)
    
    print(f"\nCICIDS2017 Train Accuracy: {tr_acc_cic:.4f} ({tr_acc_cic*100:.2f}%)")
    print(f"CICIDS2017 Test Accuracy : {te_acc_cic:.4f} ({te_acc_cic*100:.2f}%)")
    print(f"CICIDS2017 Generalization Gap (Acc): {tr_acc_cic - te_acc_cic:.4f}")
    print(f"CICIDS2017 Train Weighted F1: {tr_f1_w_cic:.4f} | Test Weighted F1: {te_f1_w_cic:.4f}")
    print(f"CICIDS2017 Train Macro F1   : {tr_f1_m_cic:.4f} | Test Macro F1   : {te_f1_m_cic:.4f}")

def audit_data_quality():
    print("\n" + "=" * 60)
    print("PHASE O: DATA QUALITY AUDIT (NaN, Inf, Negative Values)")
    print("=" * 60)
    
    # Processed datasets
    cic_train_data = np.load(os.path.join(PROCESSED_DATA_DIR, "cicids2017", "train_reduced.npz"))
    cic_test_data = np.load(os.path.join(PROCESSED_DATA_DIR, "cicids2017", "test_reduced.npz"))
    
    X_tr_cic = cic_train_data['X']
    X_te_cic = cic_test_data['X']
    
    print("CICIDS2017 Processed Quality:")
    print(f"  - Train NaN count: {np.isnan(X_tr_cic).sum()}, Inf count: {np.isinf(X_tr_cic).sum()}")
    print(f"  - Test NaN count: {np.isnan(X_te_cic).sum()}, Inf count: {np.isinf(X_te_cic).sum()}")
    
    nsl_train_data = np.load(os.path.join(PROCESSED_DATA_DIR, "nsl_kdd", "train_reduced.npz"))
    nsl_test_data = np.load(os.path.join(PROCESSED_DATA_DIR, "nsl_kdd", "test_reduced.npz"))
    
    X_tr_nsl = nsl_train_data['X']
    X_te_nsl = nsl_test_data['X']
    
    print("NSL-KDD Processed Quality:")
    print(f"  - Train NaN count: {np.isnan(X_tr_nsl).sum()}, Inf count: {np.isinf(X_tr_nsl).sum()}")
    print(f"  - Test NaN count: {np.isnan(X_te_nsl).sum()}, Inf count: {np.isinf(X_te_nsl).sum()}")
    
    # Raw CICIDS2017 inspection for negative flow durations or impossible values
    raw_sample_path = os.path.join(PROJECT_ROOT, "data", "raw", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
    df_raw = pd.read_csv(raw_sample_path, nrows=50000)
    df_raw.columns = df_raw.columns.str.strip()
    
    flow_dur_col = [c for c in df_raw.columns if "Duration" in c][0]
    neg_dur = (df_raw[flow_dur_col] < 0).sum()
    print(f"\nRaw CICIDS2017 sample ({raw_sample_path.split(os.sep)[-1]}, 50k rows):")
    print(f"  - Negative Flow Duration count: {neg_dur}")
    inf_count = np.isinf(df_raw.select_dtypes(include=[np.number])).sum().sum()
    nan_count = df_raw.isna().sum().sum()
    print(f"  - Raw Inf values: {inf_count}")
    print(f"  - Raw NaN values: {nan_count}")

def audit_adversarial_sanity():
    print("\n" + "=" * 60)
    print("PHASE N: ADVERSARIAL / SANITY TESTS")
    print("=" * 60)
    
    cic_model = joblib.load(os.path.join(ARTIFACTS_DIR, "production", "cicids2017", "best_model.joblib"))
    cic_test_data = np.load(os.path.join(PROCESSED_DATA_DIR, "cicids2017", "test_reduced.npz"))
    X_te = cic_test_data['X']
    y_te = cic_test_data['y']
    
    with open(os.path.join(ARTIFACTS_DIR, "features", "cicids2017_selected_features.json"), "r") as f:
        cic_features = json.load(f)
        
    baseline_acc = accuracy_score(y_te, cic_model.predict(X_te))
    print(f"CICIDS2017 Baseline Test Accuracy: {baseline_acc*100:.4f}%")
    
    # Test 1: Feature Permutation / Importance test on Destination Port
    dst_port_idx = cic_features.index("Destination Port")
    print(f"\nSanity Test 1: Shuffling 'Destination Port' (feature index {dst_port_idx})...")
    X_perm = X_te.copy()
    np.random.seed(42)
    np.random.shuffle(X_perm[:, dst_port_idx])
    acc_shuffled_port = accuracy_score(y_te, cic_model.predict(X_perm))
    print(f"  -> Accuracy with shuffled Destination Port: {acc_shuffled_port*100:.4f}% (Drop: {(baseline_acc - acc_shuffled_port)*100:.4f}%)")
    
    # Test 2: Shuffling Top Feature 'Bwd Packet Length Mean'
    bwd_mean_idx = cic_features.index("Bwd Packet Length Mean")
    print(f"\nSanity Test 2: Shuffling Top Feature 'Bwd Packet Length Mean' (feature index {bwd_mean_idx})...")
    X_perm2 = X_te.copy()
    np.random.shuffle(X_perm2[:, bwd_mean_idx])
    acc_shuffled_bwd = accuracy_score(y_te, cic_model.predict(X_perm2))
    print(f"  -> Accuracy with shuffled Bwd Packet Length Mean: {acc_shuffled_bwd*100:.4f}% (Drop: {(baseline_acc - acc_shuffled_bwd)*100:.4f}%)")
    
    # Test 3: Sensor Defaults Distortion Test (Simulating real sensor inputs)
    # The sensor sets Active Min/Max/Mean/Std and Idle Std to 0.0, and min_seg_size_forward to 20
    # Let's see what happens to CICIDS2017 test set when transformed with these sensor defaults
    print(f"\nSanity Test 3: Sensor Feature Realism Test (Injecting sensor defaults into test set)...")
    # Features affected in CICIDS2017:
    active_idle_cols = ["Active Min", "Active Max", "Active Mean", "Active Std", "Idle Std"]
    active_idle_indices = [cic_features.index(col) for col in active_idle_cols if col in cic_features]
    
    # Note: X_te is already standardized. Standardized 0.0 corresponds to (0.0 - mean) / std.
    # What happens if we zero out the standardized values?
    X_sensor_sim = X_te.copy()
    for idx in active_idle_indices:
        X_sensor_sim[:, idx] = 0.0  # representing mean imputation / default zeroing
        
    acc_sensor_sim = accuracy_score(y_te, cic_model.predict(X_sensor_sim))
    print(f"  -> Accuracy with sensor default Active/Idle features: {acc_sensor_sim*100:.4f}%")
    
    # Test 4: NSL-KDD Sensor Defaults Distortion Test
    nsl_model = joblib.load(os.path.join(ARTIFACTS_DIR, "production", "nsl_kdd", "best_model.joblib"))
    nsl_test_data = np.load(os.path.join(PROCESSED_DATA_DIR, "nsl_kdd", "test_reduced.npz"))
    X_te_nsl = nsl_test_data['X']
    y_te_nsl = nsl_test_data['y_5class']
    
    with open(os.path.join(ARTIFACTS_DIR, "features", "nsl_kdd_selected_features.json"), "r") as f:
        nsl_features = json.load(f)
        
    nsl_base_acc = accuracy_score(y_te_nsl, nsl_model.predict(X_te_nsl))
    print(f"\nNSL-KDD Baseline Test Accuracy: {nsl_base_acc*100:.4f}%")
    
    # The sensor hardcodes diff_srv_rate=0.0, same_srv_rate=1.0, dst_host_diff_srv_rate=0.0, dst_host_same_srv_rate=1.0
    # Let's inspect preprocessor scaler parameters for these features to accurately simulate sensor defaults
    preproc_nsl = joblib.load(os.path.join(ARTIFACTS_DIR, "preprocessors", "nsl_kdd_preprocessor.joblib"))
    num_scaler = preproc_nsl.named_transformers_['num'].named_steps['scaler']
    num_cols = preproc_nsl.transformers_[0][2]
    
    X_nsl_sensor_sim = X_te_nsl.copy()
    # Apply sensor defaults
    sensor_defaults = {
        "diff_srv_rate": 0.0,
        "same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0.0,
        "dst_host_same_srv_rate": 1.0,
        "hot": 0.0,
        "num_compromised": 0.0
    }
    
    for feat_name, default_val in sensor_defaults.items():
        if feat_name in nsl_features and feat_name in num_cols:
            col_idx_reduced = nsl_features.index(feat_name)
            col_idx_num = num_cols.index(feat_name)
            norm_val = (default_val - num_scaler.mean_[col_idx_num]) / num_scaler.scale_[col_idx_num]
            X_nsl_sensor_sim[:, col_idx_reduced] = norm_val
            
    acc_nsl_sensor_sim = accuracy_score(y_te_nsl, nsl_model.predict(X_nsl_sensor_sim))
    print(f"Sanity Test 4: NSL-KDD with Sensor Default Values (same_srv_rate=1, diff_srv_rate=0, etc.):")
    print(f"  -> Accuracy with Sensor Defaults: {acc_nsl_sensor_sim*100:.4f}% (Drop: {(nsl_base_acc - acc_nsl_sensor_sim)*100:.4f}%)")
    
    # Check what happens to attack recall under sensor defaults!
    normal_idx = 1 # 'Normal'
    benign_test = (y_te_nsl == normal_idx)
    attack_test = ~benign_test
    
    y_pred_orig = nsl_model.predict(X_te_nsl)
    y_pred_sensor = nsl_model.predict(X_nsl_sensor_sim)
    
    orig_attack_recall = np.sum(attack_test & (y_pred_orig != normal_idx)) / np.sum(attack_test)
    sensor_attack_recall = np.sum(attack_test & (y_pred_sensor != normal_idx)) / np.sum(attack_test)
    
    print(f"  -> Original Attack Recall: {orig_attack_recall*100:.2f}%")
    print(f"  -> Attack Recall under Sensor Defaults: {sensor_attack_recall*100:.2f}%")
    print(f"  -> False Negative Rate under Sensor Defaults: {(1 - sensor_attack_recall)*100:.2f}%!")

if __name__ == "__main__":
    audit_overfitting()
    audit_data_quality()
    audit_adversarial_sanity()
