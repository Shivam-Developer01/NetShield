# CICIDS2017 Model Training & Packaging Pipeline (`ml_service/training/cicids2017/`)

## Overview
This directory contains the authoritative tuning, training, and packaging scripts that produced the **NetShield CICIDS2017 Two-Stage Cascade v1.2** production model artifacts (`artifacts/v1.2/cicids2017/`).

## Architecture
- **Stage 1 (Binary Detection)**: Cost-sensitive attack detector tuned to minimize false negatives on modern high-volume attacks (DoS, DDoS, PortScan, Infiltration, Web Attacks).
- **Stage 2 (Multiclass Routing)**: Multi-class attack classifier routing detected threats to specific attack signatures.
- **Threshold Policy**: `attack_threshold = 0.40`, catching low-probability attacks before argmax.

## Scripts
- `01_investigate_false_negatives.py`: Diagnostic analysis of borderline attack flows and classification boundaries.
- `02_train_and_tune_twostage_models.py`: Tunes Stage 1 binary and Stage 2 multiclass thresholds.
- `03_train_and_evaluate_v1_2.py`: Trains the Two-Stage Cascade model on stratified CICIDS2017 training flows and evaluates once on held-out test flows.
- `04_sensor_stress_test_v1_2.py`: Stress-tests the trained pipeline with synthetic sensor flows.
- `05_test_end_to_end.py`: End-to-end inference verification.

## Artifact Target
Active production output: `artifacts/v1.2/cicids2017/`
- `best_model.joblib`
- `preprocessor.joblib`
- `feature_selector.joblib`
- `label_encoder.joblib`
- `feature_schema.json`
- `metadata.json`
