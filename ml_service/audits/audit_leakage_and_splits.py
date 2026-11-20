import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from collections import Counter

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RAW_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "raw")
PROCESSED_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "processed")
ARTIFACTS_DIR = os.path.join(PROJECT_ROOT, "artifacts")
sys.path.append(os.path.join(PROJECT_ROOT, "ml_service", "src", "features"))
sys.path.append(os.path.join(PROJECT_ROOT, "ml_service", "src", "preprocessing"))

def audit_nsl_kdd_leakage_and_splits():
    print("=" * 60)
    print("AUDITING NSL-KDD: SPLITS, DUPLICATES, & LEAKAGE")
    print("=" * 60)
    
    from nsl_kdd_preprocessor import NSL_KDD_COLUMNS, NSL_KDD_5CLASS_MAP
    
    train_path = os.path.join(RAW_DATA_DIR, "KDDTrain+.txt")
    test_path = os.path.join(RAW_DATA_DIR, "KDDTest+.txt")
    
    df_train_raw = pd.read_csv(train_path, header=None, names=NSL_KDD_COLUMNS)
    df_test_raw = pd.read_csv(test_path, header=None, names=NSL_KDD_COLUMNS)
    
    print(f"Raw KDDTrain+ shape: {df_train_raw.shape}")
    print(f"Raw KDDTest+ shape: {df_test_raw.shape}")
    
    # Check duplicates within train, within test, and cross train-test
    train_dups = df_train_raw.duplicated().sum()
    test_dups = df_test_raw.duplicated().sum()
    print(f"Exact duplicate rows in KDDTrain+: {train_dups}")
    print(f"Exact duplicate rows in KDDTest+: {test_dups}")
    
    # Overlap between train and test
    features_only = [c for c in NSL_KDD_COLUMNS if c not in ['label', 'difficulty_level']]
    
    # Exact full row overlap
    overlap_full = pd.merge(df_train_raw, df_test_raw, how='inner')
    print(f"Exact full-row overlap between KDDTrain+ and KDDTest+: {len(overlap_full)} rows")
    
    # Feature-only overlap (same features, possibly same or different label)
    overlap_feat = pd.merge(df_train_raw[features_only], df_test_raw[features_only], how='inner')
    print(f"Feature-only duplicate overlap between KDDTrain+ and KDDTest+: {len(overlap_feat)} rows")
    
    # Class distributions
    y_train_5class = df_train_raw['label'].str.lower().str.strip().map(lambda x: NSL_KDD_5CLASS_MAP.get(x, 'Other'))
    y_test_5class = df_test_raw['label'].str.lower().str.strip().map(lambda x: NSL_KDD_5CLASS_MAP.get(x, 'Other'))
    
    print(f"\nKDDTrain+ 5-class distribution:")
    print(y_train_5class.value_counts())
    print(y_train_5class.value_counts(normalize=True)*100)
    
    print(f"\nKDDTest+ 5-class distribution:")
    print(y_test_5class.value_counts())
    print(y_test_5class.value_counts(normalize=True)*100)
    
    # Check unseen attacks in KDDTest+
    train_attacks = set(df_train_raw['label'].str.lower().str.strip().unique())
    test_attacks = set(df_test_raw['label'].str.lower().str.strip().unique())
    unseen_attacks = test_attacks - train_attacks
    print(f"\nUnique raw attack types in KDDTrain+: {len(train_attacks)}")
    print(f"Unique raw attack types in KDDTest+: {len(test_attacks)}")
    print(f"Unseen attack types in KDDTest+ not in Train ({len(unseen_attacks)}): {sorted(list(unseen_attacks))}")
    
    unseen_samples = df_test_raw[df_test_raw['label'].str.lower().str.strip().isin(unseen_attacks)]
    print(f"Total test samples with unseen attack types: {len(unseen_samples)} ({len(unseen_samples)/len(df_test_raw)*100:.2f}%)")
    
    # Unseen 5-class mapping for these unseen attacks
    unseen_mapped = unseen_samples['label'].str.lower().str.strip().map(lambda x: NSL_KDD_5CLASS_MAP.get(x, 'Other'))
    print("5-class distribution of unseen attacks in test set:")
    print(unseen_mapped.value_counts())
    
    # Preprocessing leakage audit
    preproc = joblib.load(os.path.join(ARTIFACTS_DIR, "preprocessors", "nsl_kdd_preprocessor.joblib"))
    print(f"\nPreprocessor fitted type: {type(preproc).__name__}")
    # Inspect scaler means
    scaler = preproc.named_transformers_['num'].named_steps['scaler']
    print(f"Numerical features count in Scaler: {len(scaler.mean_)}")
    
    return {
        "train_samples": len(df_train_raw),
        "test_samples": len(df_test_raw),
        "train_duplicates": int(train_dups),
        "test_duplicates": int(test_dups),
        "cross_full_overlap": len(overlap_full),
        "cross_feature_overlap": len(overlap_feat),
        "unseen_attack_types_count": len(unseen_attacks),
        "unseen_samples_count": len(unseen_samples),
        "unseen_samples_pct": float(len(unseen_samples)/len(df_test_raw)*100)
    }

def audit_cicids2017_leakage_and_splits():
    print("\n" + "=" * 60)
    print("AUDITING CICIDS2017: SPLITS, DUPLICATES, & LEAKAGE")
    print("=" * 60)
    
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
    
    # Load processed data shapes
    train_npz = os.path.join(PROCESSED_DATA_DIR, "cicids2017", "train_processed.npz")
    test_npz = os.path.join(PROCESSED_DATA_DIR, "cicids2017", "test_processed.npz")
    
    train_data = np.load(train_npz)
    test_data = np.load(test_npz)
    
    X_train, y_train = train_data['X'], train_data['y']
    X_test, y_test = test_data['X'], test_data['y']
    
    print(f"X_train shape: {X_train.shape}, y_train shape: {y_train.shape}")
    print(f"X_test shape: {X_test.shape}, y_test shape: {y_test.shape}")
    print(f"Total combined rows: {len(y_train) + len(y_test)}")
    print(f"Train/Test split ratio: {len(y_train)/(len(y_train)+len(y_test))*100:.2f}% / {len(y_test)/(len(y_train)+len(y_test))*100:.2f}%")
    
    # Check class distributions
    train_counts = Counter(y_train)
    test_counts = Counter(y_test)
    
    encoder = joblib.load(os.path.join(ARTIFACTS_DIR, "encoders", "cicids2017_label_encoder.joblib"))
    classes = list(encoder.classes_)
    
    print("\nCICIDS2017 Class Distribution (Train vs Test):")
    for idx, c in enumerate(classes):
        tr_c = train_counts.get(idx, 0)
        te_c = test_counts.get(idx, 0)
        tr_pct = tr_c / len(y_train) * 100
        te_pct = te_c / len(y_test) * 100
        print(f"  [{idx:02d}] {c:<28}: Train={tr_c:7d} ({tr_pct:6.2f}%) | Test={te_c:7d} ({te_pct:6.2f}%)")
        
    # Check for exact duplicate rows within sample of train and test
    print("\nChecking for duplicate vectors in sample of X_train and X_test...")
    np.random.seed(42)
    sample_size = 50000
    sub_tr_idx = np.random.choice(len(X_train), sample_size, replace=False)
    sub_te_idx = np.random.choice(len(X_test), sample_size, replace=False)
    
    X_tr_sample = X_train[sub_tr_idx]
    X_te_sample = X_test[sub_te_idx]
    
    # Duplicate rows in train sample
    df_tr_samp = pd.DataFrame(X_tr_sample)
    df_te_samp = pd.DataFrame(X_te_sample)
    
    tr_samp_dups = df_tr_samp.duplicated().sum()
    te_samp_dups = df_te_samp.duplicated().sum()
    print(f"Duplicates in 50k train sample: {tr_samp_dups} ({tr_samp_dups/sample_size*100:.2f}%)")
    print(f"Duplicates in 50k test sample: {te_samp_dups} ({te_samp_dups/sample_size*100:.2f}%)")
    
    # Cross overlap in 50k sample
    cross_sample = pd.merge(df_tr_samp, df_te_samp, how='inner')
    print(f"Cross-split duplicate rows between 50k train sample & 50k test sample: {len(cross_sample)} rows ({len(cross_sample)/sample_size*100:.2f}%)")
    
    # Verify preprocessor leakage:
    # Was preprocessor fitted on X_train only?
    preproc = joblib.load(os.path.join(ARTIFACTS_DIR, "preprocessors", "cicids2017_preprocessor.joblib"))
    scaler = preproc.named_transformers_['num'].named_steps['scaler']
    imputer = preproc.named_transformers_['num'].named_steps['imputer']
    
    print(f"\nPreprocessor check:")
    print(f"Imputer statistics count: {len(imputer.statistics_)}")
    print(f"Scaler mean count: {len(scaler.mean_)}")
    print(f"Scaler var count: {len(scaler.var_)}")
    
    return {
        "train_samples": len(y_train),
        "test_samples": len(y_test),
        "train_sample_dup_pct": float(tr_samp_dups/sample_size*100),
        "test_sample_dup_pct": float(te_samp_dups/sample_size*100),
        "cross_sample_dup_pct": float(len(cross_sample)/sample_size*100)
    }

if __name__ == "__main__":
    nsl = audit_nsl_kdd_leakage_and_splits()
    cic = audit_cicids2017_leakage_and_splits()
    
    with open(os.path.join(PROJECT_ROOT, "scratch", "audit", "leakage_split_summary.json"), "w") as f:
        json.dump({"nsl_kdd": nsl, "cicids2017": cic}, f, indent=2)
