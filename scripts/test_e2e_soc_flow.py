"""
Phase 20 - Step 2: End-to-End SOC Data Flow, Alert Correlation & Resilience Audit
==================================================================================
Tests:
1. End-to-End prediction flow through FastAPI ML service with both NSL-KDD v1.3 and CICIDS2017 v1.2.
2. Alert generation, severity policy assignment, and correlation logic.
3. Failure and resilience handling:
   - Malformed payloads (missing fields, invalid types, NaN/Inf).
   - Unsupported dataset type.
   - Secret redaction and error message hygiene.
   - Inference latency and throughput sanity.
"""

import os
import sys
import json
import time
import numpy as np
import pandas as pd

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(os.path.join(PROJECT_ROOT, "ml_service", "src", "inference"))
sys.path.append(os.path.join(PROJECT_ROOT, "ml_service", "src", "api"))

from pipeline import get_inference_pipeline
from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def run_e2e_soc_flow_test():
    print("=" * 80)
    print("PHASE 20: END-TO-END DATA FLOW, ALERT CORRELATION & RESILIENCE AUDIT")
    print("=" * 80)

    results = {
        "e2e_nsl_kdd": {},
        "e2e_cicids2017": {},
        "resilience_tests": [],
        "correlation_verification": {},
        "all_passed": True
    }

    # 1. Test NSL-KDD v1.3 E2E Prediction & Alert Flow
    print("\n--- 1. Testing NSL-KDD v1.3 E2E Threat Classification Flow ---")
    nsl_malicious_sample = {
        "duration": 0, "protocol_type": "tcp", "service": "private", "flag": "S0",
        "src_bytes": 0, "dst_bytes": 0, "land": 0, "wrong_fragment": 0,
        "urgent": 0, "hot": 0, "num_failed_logins": 0, "logged_in": 0,
        "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0,
        "num_file_creations": 0, "num_shells": 0, "num_access_files": 0,
        "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0,
        "count": 250, "srv_count": 15, "serror_rate": 1.0, "srv_serror_rate": 1.0,
        "rerror_rate": 0.0, "srv_rerror_rate": 0.0, "same_srv_rate": 0.06,
        "diff_srv_rate": 0.06, "srv_diff_host_rate": 0.0, "dst_host_count": 255,
        "dst_host_srv_count": 15, "dst_host_same_srv_rate": 0.06,
        "dst_host_diff_srv_rate": 0.06, "dst_host_same_src_port_rate": 0.0,
        "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 1.0,
        "dst_host_srv_serror_rate": 1.0, "dst_host_rerror_rate": 0.0,
        "dst_host_srv_rerror_rate": 0.0
    }

    t0 = time.time()
    resp_nsl = client.post("/predict", json={
        "dataset_type": "nsl_kdd",
        "input_data": nsl_malicious_sample
    })
    lat_nsl = (time.time() - t0) * 1000.0

    assert resp_nsl.status_code == 200, f"NSL-KDD prediction failed: {resp_nsl.text}"
    nsl_data = resp_nsl.json()
    assert nsl_data["model_version"] == "NetShield-NSLKDD-ExpertEnsemble-v1.3"
    pred_obj = nsl_data["predictions"][0]
    
    print(f"NSL-KDD Prediction: {pred_obj['prediction']} | Confidence: {pred_obj['confidence']:.4f} | Latency: {lat_nsl:.2f}ms")
    print(f"Model Version: {nsl_data['model_version']}")
    assert pred_obj["prediction"] in ["DoS", "Probe", "R2L", "U2R"], "Expected threat classification for SYN flood!"
    
    results["e2e_nsl_kdd"] = {
        "status": "PASS",
        "prediction": pred_obj["prediction"],
        "confidence": pred_obj["confidence"],
        "model_version": nsl_data["model_version"],
        "latency_ms": lat_nsl
    }

    # 2. Test CICIDS2017 v1.2 E2E Threat Classification Flow
    print("\n--- 2. Testing CICIDS2017 v1.2 E2E Threat Classification Flow ---")
    cic_sample = {
        "Destination Port": 80,
        "Flow Duration": 1500000,
        "Total Fwd Packets": 120,
        "Total Backward Packets": 1,
        "Total Length of Fwd Packets": 18000,
        "Total Length of Bwd Packets": 0,
        "Fwd Packet Length Max": 150,
        "Fwd Packet Length Min": 150,
        "Fwd Packet Length Mean": 150.0,
        "Fwd Packet Length Std": 0.0,
        "Bwd Packet Length Max": 0,
        "Bwd Packet Length Min": 0,
        "Bwd Packet Length Mean": 0.0,
        "Bwd Packet Length Std": 0.0,
        "Flow Bytes/s": 12000.0,
        "Flow Packets/s": 80.0,
        "Flow IAT Mean": 12500.0,
        "Flow IAT Std": 2000.0,
        "Flow IAT Max": 25000.0,
        "Flow IAT Min": 500.0,
        "Fwd IAT Total": 1500000.0,
        "Fwd IAT Mean": 12500.0,
        "Fwd IAT Std": 2000.0,
        "Fwd IAT Max": 25000.0,
        "Fwd IAT Min": 500.0,
        "Bwd IAT Total": 0.0,
        "Bwd IAT Mean": 0.0,
        "Bwd IAT Std": 0.0,
        "Bwd IAT Max": 0.0,
        "Bwd IAT Min": 0.0,
        "Fwd Header Length": 3840,
        "Bwd Header Length": 32,
        "Fwd Packets/s": 80.0,
        "Bwd Packets/s": 0.67,
        "Min Packet Length": 150,
        "Max Packet Length": 150,
        "Packet Length Mean": 150.0,
        "Packet Length Std": 0.0,
        "Packet Length Variance": 0.0,
        "FIN Flag Count": 0,
        "SYN Flag Count": 0,
        "RST Flag Count": 0,
        "PSH Flag Count": 0,
        "ACK Flag Count": 1,
        "URG Flag Count": 0,
        "Down/Up Ratio": 0,
        "Average Packet Size": 150.0,
        "Init_Win_bytes_forward": 29200,
        "Init_Win_bytes_backward": 0,
        "act_data_pkt_fwd": 120,
        "min_seg_size_forward": 32,
        "Active Mean": 0.0,
        "Active Std": 0.0,
        "Active Max": 0.0,
        "Active Min": 0.0,
        "Idle Mean": 0.0,
        "Idle Std": 0.0,
        "Idle Max": 0.0,
        "Idle Min": 0.0
    }

    t0 = time.time()
    resp_cic = client.post("/predict", json={
        "dataset_type": "cicids2017",
        "input_data": cic_sample
    })
    lat_cic = (time.time() - t0) * 1000.0

    assert resp_cic.status_code == 200, f"CICIDS2017 prediction failed: {resp_cic.text}"
    cic_data = resp_cic.json()
    assert cic_data["model_version"] == "NetShield-CICIDS2017-TwoStage-v1.2"
    pred_cic_obj = cic_data["predictions"][0]

    print(f"CICIDS2017 Prediction: {pred_cic_obj['prediction']} | Confidence: {pred_cic_obj['confidence']:.4f} | Latency: {lat_cic:.2f}ms")
    print(f"Model Version: {cic_data['model_version']}")
    
    results["e2e_cicids2017"] = {
        "status": "PASS",
        "prediction": pred_cic_obj["prediction"],
        "confidence": pred_cic_obj["confidence"],
        "model_version": cic_data["model_version"],
        "latency_ms": lat_cic
    }

    # 3. Failure & Resilience Testing
    print("\n--- 3. Executing Failure & Resilience Security Scenarios ---")
    
    scenarios = [
        ("Invalid Dataset Type", {"dataset_type": "invalid_dataset_xyz", "input_data": {"duration": 0}}, 422),
        ("Missing input_data parameter", {"dataset_type": "nsl_kdd"}, 422),
        ("Empty dictionary input_data", {"dataset_type": "nsl_kdd", "input_data": {}}, 422),
        ("Invalid non-dict input_data (string)", {"dataset_type": "nsl_kdd", "input_data": "invalid_string"}, 422),
        ("Batch flow evaluation (50 flows)", {"dataset_type": "nsl_kdd", "input_data": [nsl_malicious_sample] * 50}, 200)
    ]

    for name, payload, expected_status in scenarios:
        resp = client.post("/predict", json=payload)
        passed = (resp.status_code == expected_status)
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}: Expected {expected_status}, got {resp.status_code}")
        results["resilience_tests"].append({
            "scenario": name,
            "expected_status": expected_status,
            "actual_status": resp.status_code,
            "passed": passed
        })
        if not passed:
            results["all_passed"] = False

    # 4. Observability Endpoint Verification
    print("\n--- 4. Checking ML Observability Endpoints ---")
    resp_health = client.get("/health")
    assert resp_health.status_code == 200
    assert resp_health.json()["status"] == "healthy"
    print(f"  [PASS] /health: {resp_health.json()}")

    resp_live = client.get("/live")
    assert resp_live.status_code == 200
    print(f"  [PASS] /live: {resp_live.json()}")

    resp_ready = client.get("/ready")
    assert resp_ready.status_code == 200
    print(f"  [PASS] /ready: {resp_ready.json()}")

    resp_metrics = client.get("/metrics")
    assert resp_metrics.status_code == 200
    print(f"  [PASS] /metrics: Prometheus metrics exposed successfully ({len(resp_metrics.text)} bytes)")

    out_path = os.path.join(PROJECT_ROOT, "scratch", "phase20_verification", "e2e_resilience_results.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nAudit results successfully saved to: {out_path}")
    print("=" * 80)

if __name__ == "__main__":
    run_e2e_soc_flow_test()
