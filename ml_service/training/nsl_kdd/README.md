# NSL-KDD Model Training & Packaging Pipeline (`ml_service/training/nsl_kdd/`)

## Overview
This directory contains the authoritative research, ablation, tuning, and packaging scripts that produced the **NetShield NSL-KDD Expert Ensemble v1.3** production model artifacts (`artifacts/v1.3/nsl_kdd/`).

## Architecture
- **Base Model**: Cost-sensitive 5-class XGBoost model trained on full 125,973 KDDTrain+ records.
- **Specialists**: Dedicated binary specialist models for rare attack classes (R2L and U2R).
- **Gating & Uncertainty**: Dynamic threshold-gated decision routing with uncertainty rejection.
- **Derived Features**: 14 real-time derived network features (packet/byte rates, service diversity, error ratios).

## Scripts
- `01_nsl_data_audit.py`: Audits raw NSL-KDD dataset distributions and split hygiene.
- `02_leakage_safe_experiments.py`: Verifies leakage-resistant preprocessing and cross-validation splits.
- `03_attack_holdout_experiment.py`: Tests unseen variant generalization.
- `04_feature_ablation_and_tuning.py`: Hyperparameter grid search and cost-matrix optimization.
- `05_check_r2l_test_features.py`: Feature distribution sanity check on R2L test records.
- `06_train_and_evaluate_v1_3.py`: Trains the base model and specialist ensemble.
- `07_expert_ensemble_experiments.py`: Evaluates ensemble gating parameters.
- `08_test_expert_ensemble_v1_3.py`: Evaluates ensemble on unseen attack holdouts.
- `09_package_and_verify_v1_3.py`: Serializes and freezes the active production bundle into `artifacts/v1.3/nsl_kdd/` and verifies SHA256 checksums.
- `10_audit_v1_3_consistency.py`: Production inference consistency verifier.

## Artifact Target
Active production output: `artifacts/v1.3/nsl_kdd/`
- `best_model.joblib`
- `preprocessor.joblib`
- `feature_selector.joblib`
- `label_encoder.joblib`
- `feature_schema.json`
- `metadata.json`
- `checksums.sha256`
