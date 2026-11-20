import os
import sys
import json

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

def map_pipeline():
    pipeline_info = {
        "datasets": {
            "nsl_kdd": {
                "raw_files": [
                    os.path.join("data", "raw", "KDDTrain+.txt"),
                    os.path.join("data", "raw", "KDDTest+.txt")
                ],
                "sample_counts": {
                    "raw_train": 125973,
                    "raw_test": 22544
                },
                "split_type": "Canonical benchmark split (KDDTrain+ / KDDTest+)",
                "classes": ["DoS", "Normal", "Probe", "R2L", "U2R"]
            },
            "cicids2017": {
                "raw_files": [
                    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
                    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
                    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
                    "Monday-WorkingHours.pcap_ISCX.csv",
                    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
                    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
                    "Tuesday-WorkingHours.pcap_ISCX.csv",
                    "Wednesday-workingHours.pcap_ISCX.csv"
                ],
                "sample_counts": {
                    "total_combined": 2830743,
                    "train_split": 2264594,
                    "test_split": 566149
                },
                "split_type": "Stratified random 80/20 train/test split (random_state=42)",
                "classes": 15
            }
        },
        "pipeline_files": {
            "dataset_loading": "ml_service/src/preprocessing/run_preprocessing.py",
            "splitting": "ml_service/src/preprocessing/run_preprocessing.py (line 137 for CICIDS2017; canonical files for NSL-KDD)",
            "preprocessing": [
                "ml_service/src/preprocessing/cicids2017_preprocessor.py",
                "ml_service/src/preprocessing/nsl_kdd_preprocessor.py"
            ],
            "feature_selection": [
                "ml_service/src/features/feature_selector.py",
                "ml_service/src/features/run_feature_selection.py"
            ],
            "training": [
                "ml_service/src/models/train_baseline_models.py",
                "ml_service/src/models/train_ensemble_models.py"
            ],
            "artifact_bundling": "ml_service/src/production/bundle_production_artifacts.py",
            "inference_engine": "ml_service/src/inference/pipeline.py",
            "fastapi_service": "ml_service/src/api/routes.py",
            "sensor_mapping": [
                "sensor/src/features/cicids2017Features.py",
                "sensor/src/features/nslKddFeatures.py"
            ],
            "dashboard_display": "frontend/src/pages/DashboardPage.jsx (lines 231-250)"
        }
    }
    
    with open(os.path.join(PROJECT_ROOT, "scratch", "audit", "pipeline_map.json"), "w") as f:
        json.dump(pipeline_info, f, indent=2)
    print("Pipeline map written to scratch/audit/pipeline_map.json")

if __name__ == "__main__":
    map_pipeline()
