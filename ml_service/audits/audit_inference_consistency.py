import os
import sys
import json
import joblib
import numpy as np
import pandas as pd

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.append(os.path.join(PROJECT_ROOT, "ml_service", "src", "features"))
sys.path.append(os.path.join(PROJECT_ROOT, "ml_service", "src", "preprocessing"))
sys.path.append(PROJECT_ROOT)

from ml_service.src.inference.pipeline import get_inference_pipeline
from sensor.src.features.cicids2017Features import CICIDS2017FeatureMapper
from sensor.src.features.nslKddFeatures import NSLKDDFeatureMapper

def audit_inference_consistency():
    print("=" * 60)
    print("PHASE L: INFERENCE PIPELINE CONSISTENCY AUDIT")
    print("=" * 60)
    
    pipeline = get_inference_pipeline()
    
    # 1. NSL-KDD
    bundle_nsl = pipeline.bundles["nsl_kdd"]
    preproc_nsl = bundle_nsl["preprocessor"]
    selector_nsl = bundle_nsl["selector"]
    schema_nsl = bundle_nsl["schema"]
    
    print(f"NSL-KDD Loaded Bundle:")
    print(f"  - Model: {type(bundle_nsl['model']).__name__}")
    print(f"  - Preprocessor transformers: {[t[0] for t in preproc_nsl.transformers_]}")
    print(f"  - Selector indices count: {len(selector_nsl.selected_indices)}")
    print(f"  - Feature schema count: {len(schema_nsl)}")
    
    # 2. CICIDS2017
    bundle_cic = pipeline.bundles["cicids2017"]
    preproc_cic = bundle_cic["preprocessor"]
    selector_cic = bundle_cic["selector"]
    schema_cic = bundle_cic["schema"]
    
    print(f"\nCICIDS2017 Loaded Bundle:")
    print(f"  - Model: {type(bundle_cic['model']).__name__}")
    print(f"  - Preprocessor transformers: {[t[0] for t in preproc_cic.transformers_]}")
    print(f"  - Selector indices count: {len(selector_cic.selected_indices)}")
    print(f"  - Feature schema count: {len(schema_cic)}")
    
    # Check feature name matching
    print("\nFeature schema consistency:")
    print(f"  - NSL-KDD schema matches selector feature names: {schema_nsl == selector_nsl.selected_feature_names}")
    print(f"  - CICIDS2017 schema matches selector feature names: {schema_cic == selector_cic.selected_feature_names}")

if __name__ == "__main__":
    audit_inference_consistency()
