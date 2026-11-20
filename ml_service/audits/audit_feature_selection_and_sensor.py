import os
import sys
import json
import joblib
import pandas as pd
import numpy as np

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ARTIFACTS_DIR = os.path.join(PROJECT_ROOT, "artifacts")
sys.path.append(os.path.join(PROJECT_ROOT, "ml_service", "src", "features"))

def audit_features():
    print("=" * 60)
    print("AUDITING FEATURE SELECTION & SENSOR COMPATIBILITY")
    print("=" * 60)
    
    # 1. NSL-KDD
    with open(os.path.join(ARTIFACTS_DIR, "features", "nsl_kdd_selected_features.json"), "r") as f:
        nsl_selected = json.load(f)
        
    with open(os.path.join(ARTIFACTS_DIR, "features", "nsl_kdd_features.json"), "r") as f:
        nsl_all = json.load(f)
        
    print(f"NSL-KDD Baseline Transformed Features: {len(nsl_all)}")
    print(f"NSL-KDD Selected Features Count: {len(nsl_selected)}")
    print("NSL-KDD Selected Features:")
    for idx, f_name in enumerate(nsl_selected, 1):
        print(f"  {idx:2d}. {f_name}")
        
    # 2. CICIDS2017
    with open(os.path.join(ARTIFACTS_DIR, "features", "cicids2017_selected_features.json"), "r") as f:
        cic_selected = json.load(f)
        
    with open(os.path.join(ARTIFACTS_DIR, "features", "cicids2017_features.json"), "r") as f:
        cic_all = json.load(f)
        
    print(f"\nCICIDS2017 Baseline Transformed Features: {len(cic_all)}")
    print(f"CICIDS2017 Selected Features Count: {len(cic_selected)}")
    print("CICIDS2017 Selected Features:")
    for idx, f_name in enumerate(cic_selected, 1):
        print(f"  {idx:2d}. {f_name}")
        
    # Check feature importance JSON
    with open(os.path.join(ARTIFACTS_DIR, "metadata", "cicids2017_feature_importance.json"), "r") as f:
        cic_fi = json.load(f)
    print("\nTop 10 CICIDS2017 features by composite score:")
    for row in cic_fi[:10]:
        print(f"  - {row['feature_name']}: composite={row['composite_score']:.4f}, mi={row['mi_score']:.4f}, rf={row['rf_score']:.4f}")
        
    with open(os.path.join(ARTIFACTS_DIR, "metadata", "nsl_kdd_feature_importance.json"), "r") as f:
        nsl_fi = json.load(f)
    print("\nTop 10 NSL-KDD features by composite score:")
    for row in nsl_fi[:10]:
        print(f"  - {row['feature_name']}: composite={row['composite_score']:.4f}, mi={row['mi_score']:.4f}, rf={row['rf_score']:.4f}")

if __name__ == "__main__":
    audit_features()
