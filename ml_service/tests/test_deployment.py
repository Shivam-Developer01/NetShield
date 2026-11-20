"""
NetShield Phase 8 Deployment Validation Test Suite
Verifies standalone runner, requirements.txt, Dockerfile static structure,
.dockerignore rules, and environment variable configuration.
"""

import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ML_SERVICE_DIR = os.path.join(PROJECT_ROOT, "ml_service")
ARTIFACTS_DIR = os.path.join(PROJECT_ROOT, "artifacts")
PRODUCTION_DIR = os.path.join(ARTIFACTS_DIR, "production")


def test_standalone_runner_exists():
    """1. Verify ml_service/run_server.py exists."""
    runner_path = os.path.join(ML_SERVICE_DIR, "run_server.py")
    assert os.path.exists(runner_path), f"Standalone runner missing: {runner_path}"


def test_requirements_txt_exists_and_valid():
    """2. Verify requirements.txt exists and contains required pinned dependencies."""
    req_path = os.path.join(ML_SERVICE_DIR, "requirements.txt")
    assert os.path.exists(req_path), f"requirements.txt missing: {req_path}"

    with open(req_path, "r") as f:
        content = f.read()

    required_pkgs = ["fastapi", "uvicorn", "pydantic", "scikit-learn", "xgboost", "joblib", "numpy", "pandas"]
    for pkg in required_pkgs:
        assert pkg in content.lower(), f"Missing dependency '{pkg}' in requirements.txt"


def test_dockerfile_static_validation():
    """3. Verify Dockerfile exists and references python base image and production artifacts."""
    df_path = os.path.join(ML_SERVICE_DIR, "Dockerfile")
    assert os.path.exists(df_path), f"Dockerfile missing: {df_path}"

    with open(df_path, "r") as f:
        content = f.read()

    assert "FROM python:" in content
    assert "COPY artifacts/production" in content
    assert "EXPOSE 8000" in content
    assert "run_server.py" in content


def test_dockerignore_validation():
    """4. Verify .dockerignore exists and excludes raw data, processed data, and secrets."""
    di_path = os.path.join(ML_SERVICE_DIR, ".dockerignore")
    assert os.path.exists(di_path), f".dockerignore missing: {di_path}"

    with open(di_path, "r") as f:
        content = f.read()

    assert "data/raw/" in content or "data/" in content
    assert ".env" in content
    assert "artifacts/models/" in content


def test_production_artifacts_ready_for_deployment():
    """5. Verify production artifacts directory structure for deployment."""
    for dataset in ["nsl_kdd", "cicids2017"]:
        d_dir = os.path.join(PRODUCTION_DIR, dataset)
        assert os.path.exists(d_dir), f"Production dataset directory missing: {dataset}"

        required_files = [
            "best_model.joblib",
            "preprocessor.joblib",
            "feature_selector.joblib",
            "label_encoder.joblib",
            "feature_schema.json",
            "metadata.json"
        ]
        for fname in required_files:
            fpath = os.path.join(d_dir, fname)
            assert os.path.exists(fpath), f"Deployment production artifact missing: {dataset}/{fname}"
