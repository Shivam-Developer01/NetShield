"""
NetShield Master Validation Test Runner
Runs Phase 2, Phase 3, Phase 4, Phase 5, Phase 6, Phase 7, and Phase 8 validation tests.
"""

import sys
import os
import time

sys.path.append(os.path.dirname(__file__))

from test_preprocessing import (
    test_raw_datasets_exist_and_unchanged,
    test_nsl_kdd_processed_artifacts_and_shapes,
    test_cicids2017_processed_artifacts_and_shapes
)
from test_feature_selection import (
    test_nsl_kdd_feature_selection_artifacts,
    test_cicids2017_feature_selection_artifacts
)
from test_baseline_models import (
    test_nsl_kdd_baseline_models,
    test_cicids2017_baseline_models,
    test_baseline_eval_metadata
)
from test_ensemble_models import (
    test_nsl_kdd_ensemble_models,
    test_cicids2017_ensemble_models,
    test_ensemble_eval_metadata
)
from test_production_inference import (
    test_production_artifacts_exist,
    test_nsl_kdd_end_to_end_production_inference,
    test_cicids2017_end_to_end_production_inference
)
from test_api import (
    test_api_health_endpoint,
    test_api_model_info_endpoint,
    test_api_predict_nsl_kdd_valid,
    test_api_predict_cicids2017_valid,
    test_api_predict_invalid_dataset_type,
    test_api_predict_nan_inf_rejected
)
from test_deployment import (
    test_standalone_runner_exists,
    test_requirements_txt_exists_and_valid,
    test_dockerfile_static_validation,
    test_dockerignore_validation,
    test_production_artifacts_ready_for_deployment
)


def run_all_tests():
    print("=" * 60)
    print("RUNNING NETSHIELD VALIDATION SUITE (PHASES 2, 3, 4, 5, 6, 7 & 8)")
    print("=" * 60)

    print("[TEST 1/24] Verifying raw dataset integrity...")
    test_raw_datasets_exist_and_unchanged()
    print("  -> PASSED: Raw datasets intact and unmodified.")

    print("[TEST 2/24] Verifying NSL-KDD preprocessing artifacts & shapes...")
    test_nsl_kdd_processed_artifacts_and_shapes()
    print("  -> PASSED: NSL-KDD preprocessor, baseline shapes, and zero NaNs/Infs verified.")

    print("[TEST 3/24] Verifying CICIDS2017 preprocessing artifacts & shapes...")
    test_cicids2017_processed_artifacts_and_shapes()
    print("  -> PASSED: CICIDS2017 preprocessor, baseline shapes, and zero NaNs/Infs verified.")

    print("[TEST 4/24] Verifying NSL-KDD feature selection artifacts & reduced shapes...")
    test_nsl_kdd_feature_selection_artifacts()
    print("  -> PASSED: NSL-KDD feature selector, selected JSON schema, and reduced shapes verified.")

    print("[TEST 5/24] Verifying CICIDS2017 feature selection artifacts & reduced shapes...")
    test_cicids2017_feature_selection_artifacts()
    print("  -> PASSED: CICIDS2017 feature selector, selected JSON schema, and reduced shapes verified.")

    print("[TEST 6/24] Verifying NSL-KDD baseline model joblib artifacts & predictions...")
    test_nsl_kdd_baseline_models()
    print("  -> PASSED: NSL-KDD baseline models reloaded, 37-feature inputs accepted, predictions valid.")

    print("[TEST 7/24] Verifying CICIDS2017 baseline model joblib artifacts & predictions...")
    test_cicids2017_baseline_models()
    print("  -> PASSED: CICIDS2017 baseline models reloaded, 43-feature inputs accepted, predictions valid.")

    print("[TEST 8/24] Verifying baseline evaluation metadata...")
    test_baseline_eval_metadata()
    print("  -> PASSED: Baseline evaluation JSON metadata verified.")

    print("[TEST 9/24] Verifying NSL-KDD ensemble model joblib artifacts & predictions...")
    test_nsl_kdd_ensemble_models()
    print("  -> PASSED: NSL-KDD ensemble models reloaded, 37-feature inputs accepted, predictions valid.")

    print("[TEST 10/24] Verifying CICIDS2017 ensemble model joblib artifacts & predictions...")
    test_cicids2017_ensemble_models()
    print("  -> PASSED: CICIDS2017 ensemble models reloaded, 43-feature inputs accepted, predictions valid.")

    print("[TEST 11/24] Verifying ensemble evaluation metadata...")
    test_ensemble_eval_metadata()
    print("  -> PASSED: Ensemble evaluation JSON metadata verified.")

    print("[TEST 12/24] Verifying production bundle artifacts in artifacts/production/...")
    test_production_artifacts_exist()
    print("  -> PASSED: Production model bundles exist for nsl_kdd and cicids2017.")

    print("[TEST 13/24] Verifying NSL-KDD end-to-end production inference pipeline...")
    test_nsl_kdd_end_to_end_production_inference()
    print("  -> PASSED: NSL-KDD 5-step inference chain executed cleanly (raw -> preprocessor -> selector -> model -> decoder).")

    print("[TEST 14/24] Verifying CICIDS2017 end-to-end production inference pipeline...")
    test_cicids2017_end_to_end_production_inference()
    print("  -> PASSED: CICIDS2017 5-step inference chain executed cleanly (raw -> preprocessor -> selector -> model -> decoder).")

    print("[TEST 15/24] Verifying FastAPI GET /health endpoint...")
    test_api_health_endpoint()
    print("  -> PASSED: GET /health returned 200 OK with status='healthy' and loaded models.")

    print("[TEST 16/24] Verifying FastAPI GET /model-info endpoint...")
    test_api_model_info_endpoint()
    print("  -> PASSED: GET /model-info returned active metadata for nsl_kdd and cicids2017.")

    print("[TEST 17/24] Verifying FastAPI POST /predict (NSL-KDD)...")
    start_t = time.time()
    test_api_predict_nsl_kdd_valid()
    nsl_latency = (time.time() - start_t) * 1000.0
    print(f"  -> PASSED: NSL-KDD prediction successful (Local single request latency: {nsl_latency:.2f} ms).")

    print("[TEST 18/24] Verifying FastAPI POST /predict (CICIDS2017)...")
    start_t = time.time()
    test_api_predict_cicids2017_valid()
    cic_latency = (time.time() - start_t) * 1000.0
    print(f"  -> PASSED: CICIDS2017 prediction successful (Local single request latency: {cic_latency:.2f} ms).")

    print("[TEST 19/24] Verifying FastAPI input validation & error sanitization...")
    test_api_predict_invalid_dataset_type()
    test_api_predict_nan_inf_rejected()
    print("  -> PASSED: Invalid dataset_type and NaN/Inf inputs correctly rejected with HTTP 422.")

    print("[TEST 20/24] Verifying standalone runner script (ml_service/run_server.py)...")
    test_standalone_runner_exists()
    print("  -> PASSED: Standalone server runner script verified.")

    print("[TEST 21/24] Verifying deployment requirements.txt dependencies...")
    test_requirements_txt_exists_and_valid()
    print("  -> PASSED: Minimal requirements.txt verified with pinned versions.")

    print("[TEST 22/24] Verifying Dockerfile static configuration...")
    test_dockerfile_static_validation()
    print("  -> PASSED: Dockerfile structure verified.")

    print("[TEST 23/24] Verifying .dockerignore exclusion rules...")
    test_dockerignore_validation()
    print("  -> PASSED: .dockerignore rules verified (excludes raw datasets and secrets).")

    print("[TEST 24/24] Verifying deployment production artifact bundle readiness...")
    test_production_artifacts_ready_for_deployment()
    print("  -> PASSED: Deployment artifact bundles ready for containerization.")

    print("=" * 60)
    print("ALL VALIDATION TESTS PASSED SUCCESSFULLY (24/24)!")
    print("=" * 60)


if __name__ == "__main__":
    run_all_tests()
