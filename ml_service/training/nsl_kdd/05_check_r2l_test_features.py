"""
Diagnostic script to inspect R2L attack feature vectors in KDDTest+.
"""
import os
import sys
import pandas as pd
import numpy as np

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
RAW_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "raw")
sys.path.append(os.path.join(PROJECT_ROOT, "ml_service", "src", "preprocessing"))
from nsl_kdd_preprocessor import NSL_KDD_COLUMNS

test_path = os.path.join(RAW_DATA_DIR, "KDDTest+.txt")
df_test = pd.read_csv(test_path, header=None, names=NSL_KDD_COLUMNS)

print("Checking guess_passwd in KDDTest+:")
gp = df_test[df_test["label"].str.strip() == "guess_passwd"]
print(f"Total count: {len(gp)}")
print(gp[["service", "flag", "src_bytes", "dst_bytes", "num_failed_logins", "logged_in", "hot", "count", "srv_count"]].describe())
print("\nTop services for guess_passwd:")
print(gp["service"].value_counts())
print("\nTop flags for guess_passwd:")
print(gp["flag"].value_counts())

print("\nChecking snmpguess in KDDTest+:")
sg = df_test[df_test["label"].str.strip() == "snmpguess"]
print(f"Total count: {len(sg)}")
print(sg[["protocol_type", "service", "flag", "src_bytes", "dst_bytes", "count", "srv_count"]].describe())
print(sg["service"].value_counts())
