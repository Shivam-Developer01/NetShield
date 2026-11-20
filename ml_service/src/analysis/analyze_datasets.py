"""
NetShield Phase 1: Reproducible Dataset Analysis Script
Analyzes raw NSL-KDD and CICIDS2017 benchmark datasets in data/raw/
WITHOUT modifying, overwriting, or preprocessing any raw files.
Memory-conscious stream processing for 8GB RAM development machine.
"""

import os
import sys
import json
from collections import Counter
import pandas as pd
import numpy as np

# Force unbuffered UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

RAW_DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "raw"))

# Official NSL-KDD Column Names (43 columns)
NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty_level"
]

NSL_KDD_ATTACK_MAP = {
    'normal': 'Normal',
    # DoS
    'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS', 'pod': 'DoS', 'smurf': 'DoS',
    'teardrop': 'DoS', 'apache2': 'DoS', 'udpstorm': 'DoS', 'processtable': 'DoS', 'mailbomb': 'DoS',
    # Probe
    'satan': 'Probe', 'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 'mscan': 'Probe', 'saint': 'Probe',
    # R2L
    'guess_passwd': 'R2L', 'ftp_write': 'R2L', 'imap': 'R2L', 'phf': 'R2L', 'multihop': 'R2L',
    'warezmaster': 'R2L', 'warezclient': 'R2L', 'spy': 'R2L', 'xlock': 'R2L', 'xsnoop': 'R2L',
    'snmpguess': 'R2L', 'snmpgetattack': 'R2L', 'httptunnel': 'R2L', 'sendmail': 'R2L', 'named': 'R2L',
    # U2R
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'rootkit': 'U2R', 'perl': 'U2R',
    'sqlattack': 'U2R', 'xterm': 'U2R', 'ps': 'U2R'
}

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


def format_bytes(size_bytes):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"


def log(msg):
    print(msg, flush=True)


def analyze_nsl_kdd():
    log("=" * 60)
    log("ANALYZING NSL-KDD DATASET")
    log("=" * 60)
    
    results = {}
    nsl_files = ["KDDTrain+.txt", "KDDTest+.txt"]
    
    for filename in nsl_files:
        filepath = os.path.join(RAW_DATA_DIR, filename)
        if not os.path.exists(filepath):
            log(f"[ERROR] Missing file: {filepath}")
            continue
            
        file_size = os.path.getsize(filepath)
        df = pd.read_csv(filepath, header=None, names=NSL_KDD_COLUMNS)
        
        row_count, col_count = df.shape
        missing_count = int(df.isnull().sum().sum())
        duplicate_count = int(df.duplicated().sum())
        
        cat_cols = [col for col in df.columns if df[col].dtype == 'object']
        num_cols = [col for col in df.columns if df[col].dtype != 'object']
        
        raw_class_dist = df['label'].value_counts().to_dict()
        df['major_class'] = df['label'].map(lambda x: NSL_KDD_ATTACK_MAP.get(str(x).lower().strip(), 'Other'))
        major_class_dist = df['major_class'].value_counts().to_dict()
        
        constant_cols = [col for col in df.columns if df[col].nunique() <= 1]
        
        log(f"File: {filename}")
        log(f"  - Size: {format_bytes(file_size)}")
        log(f"  - Shape: {row_count} rows x {col_count} columns")
        log(f"  - Missing Values: {missing_count}")
        log(f"  - Duplicate Records: {duplicate_count}")
        log(f"  - Categorical Features ({len(cat_cols)}): {cat_cols}")
        log(f"  - Numerical Features ({len(num_cols)}): Count = {len(num_cols)}")
        log(f"  - Major Class Distribution: {major_class_dist}")
        log(f"  - Constant Features: {constant_cols}")
        log("")
        
        results[filename] = {
            "file_size": file_size,
            "formatted_size": format_bytes(file_size),
            "rows": row_count,
            "columns": col_count,
            "missing_values": missing_count,
            "duplicate_records": duplicate_count,
            "categorical_features": cat_cols,
            "numerical_features": num_cols,
            "raw_class_distribution": {str(k): int(v) for k, v in raw_class_dist.items()},
            "major_class_distribution": {str(k): int(v) for k, v in major_class_dist.items()},
            "constant_features": constant_cols,
            "leakage_features": ["difficulty_level"]
        }
        
    return results


def analyze_cicids2017():
    log("=" * 60)
    log("ANALYZING CICIDS2017 DATASET")
    log("=" * 60)
    
    file_results = {}
    combined_label_dist = Counter()
    all_columns_set = set()
    total_rows = 0
    total_nan_count = 0
    total_inf_count = 0
    total_duplicates = 0
    total_size_bytes = 0
    
    col_min_max = {}
    col_types = {}
    
    for filename in CICIDS2017_FILES:
        filepath = os.path.join(RAW_DATA_DIR, filename)
        if not os.path.exists(filepath):
            log(f"[ERROR] Missing file: {filepath}")
            continue
            
        file_size = os.path.getsize(filepath)
        total_size_bytes += file_size
        
        log(f"Processing {filename} ({format_bytes(file_size)})...")
        df = pd.read_csv(filepath, low_memory=False)
        df.columns = df.columns.str.strip()
        
        row_count, col_count = df.shape
        total_rows += row_count
        
        label_col = 'Label' if 'Label' in df.columns else [c for c in df.columns if 'label' in c.lower()][0]
        
        # Calculate NaN & Inf memory-consciously per column
        nan_count = 0
        inf_count = 0
        for col in df.columns:
            if col == label_col:
                continue
            all_columns_set.add(col)
            col_types[col] = str(df[col].dtype)
            
            # Check nulls
            null_sum = df[col].isnull().sum()
            nan_count += null_sum
            
            # Check numeric infs
            if pd.api.types.is_numeric_dtype(df[col]):
                inf_sum = np.isinf(df[col].to_numpy(dtype=np.float64, na_value=0.0)).sum()
                inf_count += inf_sum
                
                c_min = df[col].min(skipna=True)
                c_max = df[col].max(skipna=True)
                if col not in col_min_max:
                    col_min_max[col] = (c_min, c_max)
                else:
                    prev_min, prev_max = col_min_max[col]
                    col_min_max[col] = (min(prev_min, c_min), max(prev_max, c_max))

        total_nan_count += int(nan_count)
        total_inf_count += int(inf_count)
        
        duplicate_count = int(df.duplicated().sum())
        total_duplicates += duplicate_count
        
        class_dist = df[label_col].astype(str).str.strip().value_counts().to_dict()
        for k, v in class_dist.items():
            combined_label_dist[k] += int(v)
            
        file_results[filename] = {
            "file_size": file_size,
            "formatted_size": format_bytes(file_size),
            "rows": row_count,
            "columns": col_count,
            "nan_count": int(nan_count),
            "inf_count": int(inf_count),
            "duplicate_records": duplicate_count,
            "class_distribution": {str(k): int(v) for k, v in class_dist.items()}
        }
        
        # Free dataframe memory immediately
        del df

    log("-" * 60)
    log(f"CICIDS2017 TOTAL SUMMARY across {len(file_results)} files:")
    log(f"  - Total Size: {format_bytes(total_size_bytes)}")
    log(f"  - Total Rows: {total_rows}")
    log(f"  - Column Count per file: {len(all_columns_set)} unique feature columns + 1 Label column")
    log(f"  - Combined Unique Labels ({len(combined_label_dist)}):")
    for lbl, count in combined_label_dist.most_common():
        percentage = (count / total_rows) * 100
        log(f"      {lbl:35s}: {count:10d} ({percentage:6.2f}%)")
    
    # Identify constant features (min == max)
    constant_features = [col for col, (c_min, c_max) in col_min_max.items() if c_min == c_max]
    
    summary = {
        "files": file_results,
        "total_size_bytes": total_size_bytes,
        "formatted_total_size": format_bytes(total_size_bytes),
        "total_rows": total_rows,
        "column_count": len(all_columns_set) + 1,
        "columns": sorted(list(all_columns_set)),
        "numerical_features_count": len(all_columns_set),
        "categorical_features": [],
        "constant_features": constant_features,
        "combined_class_distribution": dict(combined_label_dist),
        "total_nan_count": total_nan_count,
        "total_inf_count": total_inf_count,
        "total_missing_combined": total_nan_count + total_inf_count,
        "total_duplicates_sum": total_duplicates
    }
    
    return summary


def main():
    os.makedirs(RAW_DATA_DIR, exist_ok=True)
    
    nsl_summary = analyze_nsl_kdd()
    cic_summary = analyze_cicids2017()
    
    output = {
        "nsl_kdd": nsl_summary,
        "cicids2017": cic_summary
    }
    
    out_json_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "dataset_analysis_results.json"))
    with open(out_json_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
        
    log("=" * 60)
    log(f"ANALYSIS COMPLETE. Results written to: {out_json_path}")
    log("=" * 60)


if __name__ == "__main__":
    main()
