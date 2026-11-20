# NetShield ML Audits & Provenance Verification (`ml_service/audits/`)

## Overview
This directory preserves historical ML integrity, leakage prevention, dataset split, and model reproducibility verification suites.

## Audit Suites
- `audit_leakage_and_splits.py`: Checks exact and near-duplicate rows between training and test sets.
- `audit_overfitting_and_sanity.py`: Validates cross-validation generalization gaps and checks against trivial majority-class prediction.
- `audit_feature_selection_and_sensor.py`: Validates feature alignment between sensor flow extraction and model schemas.
- `audit_inference_consistency.py`: Asserts batch vs single-record inference parity.
- `audit_pipeline_map.py`: Verifies feature order preservation across sklearn pipelines.
- `audit_reproduce_metrics.py`: Re-evaluates saved production artifacts against reference metadata.
- `audit_reproducibility_test.py`: Fast reproducibility check across all frozen bundles.
- `audit_sensor_inference_test.py`: Verifies end-to-end inference using sensor-extracted features.
- `leakage_split_summary.json` & `reproduction_summary.json`: Reference JSON metric summaries from Phase 19 audit.
