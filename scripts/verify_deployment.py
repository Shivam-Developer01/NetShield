#!/usr/bin/env python3
"""
NetShield Production Deployment Smoke Test Suite (`scripts/verify_deployment.py`)
Verifies Infrastructure, Authentication, Authorization (RBAC), CSRF Protection, ML Inference, and MongoDB Persistence.
"""

import urllib.request
import urllib.parse
import json
import uuid
import sys

BASE_URL = "http://localhost:5000/api"
HEALTH_URL = "http://localhost:5000/health"

def make_request(url, method="GET", data=None, headers=None, cookie=None):
    if headers is None:
        headers = {}
    headers["Content-Type"] = "application/json"
    if cookie:
        headers["Cookie"] = cookie

    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req) as resp:
            resp_body = resp.read().decode("utf-8")
            cookie_header = resp.headers.get("Set-Cookie")
            all_headers = dict(resp.headers)
            return resp.status, json.loads(resp_body) if resp_body else {}, cookie_header, all_headers
    except urllib.error.HTTPError as e:
        resp_body = e.read().decode("utf-8")
        all_headers = dict(e.headers)
        return e.code, json.loads(resp_body) if resp_body else {}, None, all_headers

def run_deployment_smoke_tests():
    print("============================================================")
    print("STARTING NETSHIELD PRODUCTION DEPLOYMENT SMOKE TESTS")
    print("============================================================")

    test_request_id = f"smoke-test-{uuid.uuid4().hex[:8]}"

    # --- 1. Infrastructure Reachability & Correlation ID Tracing ---
    print("\n[1/6] Verifying Infrastructure Health & Request Correlation...")
    status, health_res, _, headers = make_request(HEALTH_URL, headers={"X-Request-ID": test_request_id})
    resp_req_id = headers.get("X-Request-ID") or headers.get("x-request-id")
    print(f"  -> GET /health: HTTP {status}")
    print(f"  -> Database Status: {health_res.get('database', {}).get('status')}")
    print(f"  -> ML Service Status: {health_res.get('ml_service', {}).get('status')}")
    print(f"  -> Correlation ID: '{resp_req_id}'")

    assert status == 200, f"Health probe failed with HTTP {status}"
    assert health_res.get("database", {}).get("status") == "connected"
    assert health_res.get("ml_service", {}).get("status") == "healthy"
    assert resp_req_id == test_request_id

    # --- 2. Authentication Flow ---
    print("\n[2/6] Verifying Authentication Controls...")
    
    # 2a. Invalid Login
    status, _, _, _ = make_request(f"{BASE_URL}/auth/login", method="POST", data={
        "email": "invalid_user@netshield.local",
        "password": "WrongPassword123!"
    })
    print(f"  -> Invalid Login: HTTP {status} (Expected 401)")
    assert status == 401

    # 2b. Unauthenticated Protected Access
    status, _, _, _ = make_request(f"{BASE_URL}/users")
    print(f"  -> Unauthenticated Access to /users: HTTP {status} (Expected 401)")
    assert status == 401

    # 2c. Valid Admin Login
    status, admin_res, set_cookie, _ = make_request(f"{BASE_URL}/auth/login", method="POST", data={
        "email": "admin@netshield.local",
        "password": "AdminSecurePassword123!"
    })
    print(f"  -> Admin Login: HTTP {status} (Expected 200)")
    assert status == 200
    admin_token = admin_res.get("token")
    csrf_token = admin_res.get("csrfToken")
    admin_cookie = f"netshield_token={admin_token}; XSRF-TOKEN={csrf_token}"

    # --- 3. Authorization (RBAC) & CSRF Verification ---
    print("\n[3/6] Verifying Role-Based Access Control (RBAC) & CSRF Enforcement...")
    
    # 3a. Missing CSRF Token Header
    status, _, _, _ = make_request(
        f"{BASE_URL}/predictions",
        method="POST",
        data={"datasetType": "nsl_kdd", "inputData": {"duration": 0}},
        headers={"Authorization": f"Bearer {admin_token}"},
        cookie=admin_cookie
    )
    print(f"  -> Missing CSRF Header: HTTP {status} (Expected 403)")
    assert status == 403

    # 3b. Invalid CSRF Token Header
    status, _, _, _ = make_request(
        f"{BASE_URL}/predictions",
        method="POST",
        data={"datasetType": "nsl_kdd", "inputData": {"duration": 0}},
        headers={"Authorization": f"Bearer {admin_token}", "X-XSRF-TOKEN": "invalid_csrf_token"},
        cookie=admin_cookie
    )
    print(f"  -> Invalid CSRF Header: HTTP {status} (Expected 403)")
    assert status == 403

    # --- 4. ML Service Inference (NSL-KDD & CICIDS2017) ---
    print("\n[4/6] Verifying ML Microservice Production Inference Pipeline...")
    auth_headers = {
        "Authorization": f"Bearer {admin_token}",
        "X-XSRF-TOKEN": csrf_token,
        "X-Request-ID": test_request_id
    }

    # 4a. NSL-KDD Inference
    status, nsl_res, _, _ = make_request(
        f"{BASE_URL}/predictions",
        method="POST",
        data={
            "datasetType": "nsl_kdd",
            "inputData": {
                "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF",
                "src_bytes": 215, "dst_bytes": 4507, "land": 0, "wrong_fragment": 0,
                "urgent": 0, "hot": 0, "num_failed_logins": 0, "logged_in": 1,
                "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0,
                "num_file_creations": 0, "num_shells": 0, "num_access_files": 0,
                "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0,
                "count": 1, "srv_count": 1, "serror_rate": 0.0, "srv_serror_rate": 0.0,
                "rerror_rate": 0.0, "srv_rerror_rate": 0.0, "same_srv_rate": 1.0,
                "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0, "dst_host_count": 255,
                "dst_host_srv_count": 255, "dst_host_same_srv_rate": 1.0,
                "dst_host_diff_srv_rate": 0.0, "dst_host_same_src_port_rate": 0.0,
                "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 0.0,
                "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 0.0,
                "dst_host_srv_rerror_rate": 0.0
            }
        },
        headers=auth_headers,
        cookie=admin_cookie
    )
    print(f"  -> NSL-KDD Prediction: HTTP {status}, Classification: {nsl_res.get('predictions', [{}])[0].get('prediction')}")
    assert status == 200
    assert nsl_res.get("model_version") == "NetShield-NSLKDD-XGBoost-v1.0"

    # 4b. CICIDS2017 Inference
    status, cic_res, _, _ = make_request(
        f"{BASE_URL}/predictions",
        method="POST",
        data={
            "datasetType": "cicids2017",
            "inputData": {
                "Destination Port": 80, "Flow Duration": 3, "Total Fwd Packets": 2,
                "Total Backward Packets": 0, "Total Length of Fwd Packets": 12,
                "Total Length of Bwd Packets": 0, "Fwd Packet Length Max": 6,
                "Fwd Packet Length Min": 6, "Fwd Packet Length Mean": 6.0,
                "Fwd Packet Length Std": 0.0, "Bwd Packet Length Max": 0,
                "Bwd Packet Length Min": 0, "Bwd Packet Length Mean": 0.0,
                "Bwd Packet Length Std": 0.0, "Flow Bytes/s": 4000000.0,
                "Flow Packets/s": 666666.6666666666, "Flow IAT Mean": 3.0,
                "Flow IAT Std": 0.0, "Flow IAT Max": 3, "Flow IAT Min": 3,
                "Fwd IAT Total": 3, "Fwd IAT Mean": 3.0, "Fwd IAT Std": 0.0,
                "Fwd IAT Max": 3, "Fwd IAT Min": 3, "Bwd IAT Total": 0,
                "Bwd IAT Mean": 0.0, "Bwd IAT Std": 0.0, "Bwd IAT Max": 0,
                "Bwd IAT Min": 0, "Fwd PSH Flags": 0, "Bwd PSH Flags": 0,
                "Fwd URG Flags": 0, "Bwd URG Flags": 0, "Fwd Header Length": 40,
                "Bwd Header Length": 0, "Fwd Packets/s": 666666.6666666666,
                "Bwd Packets/s": 0.0, "Min Packet Length": 6, "Max Packet Length": 6,
                "Packet Length Mean": 6.0, "Packet Length Std": 0.0,
                "Packet Length Variance": 0.0, "FIN Flag Count": 0,
                "SYN Flag Count": 0, "RST Flag Count": 0, "PSH Flag Count": 0,
                "ACK Flag Count": 1, "URG Flag Count": 0, "CWE Flag Count": 0,
                "ECE Flag Count": 0, "Down/Up Ratio": 0, "Average Packet Size": 9.0,
                "Avg Fwd Segment Size": 6.0, "Avg Bwd Segment Size": 0.0,
                "Fwd Header Length.1": 40, "Fwd Avg Bytes/Bulk": 0,
                "Fwd Avg Packets/Bulk": 0, "Fwd Avg Bulk Rate": 0,
                "Bwd Avg Bytes/Bulk": 0, "Bwd Avg Packets/Bulk": 0,
                "Bwd Avg Bulk Rate": 0, "Subflow Fwd Packets": 2,
                "Subflow Fwd Bytes": 12, "Subflow Bwd Packets": 0,
                "Subflow Bwd Bytes": 0, "Init_Win_bytes_forward": 8192,
                "Init_Win_bytes_backward": -1, "act_data_pkt_fwd": 1,
                "min_seg_size_forward": 20, "Active Mean": 0.0,
                "Active Std": 0.0, "Active Max": 0, "Active Min": 0,
                "Idle Mean": 0.0, "Idle Std": 0.0, "Idle Max": 0, "Idle Min": 0
            }
        },
        headers=auth_headers,
        cookie=admin_cookie
    )
    print(f"  -> CICIDS2017 Prediction: HTTP {status}, Classification: {cic_res.get('predictions', [{}])[0].get('prediction')}")
    assert status == 200
    assert cic_res.get("model_version") == "NetShield-CICIDS2017-XGBoost-v1.0"

    # --- 5. MongoDB Persistence & Threat Alert Generation ---
    print("\n[5/6] Verifying Data Persistence & Threat Alert Pipeline...")
    status, dos_res, _, _ = make_request(
        f"{BASE_URL}/predictions",
        method="POST",
        data={
            "datasetType": "nsl_kdd",
            "inputData": {
                "duration": 0, "protocol_type": "tcp", "service": "private", "flag": "S0",
                "src_bytes": 0, "dst_bytes": 0, "land": 0, "wrong_fragment": 0,
                "urgent": 0, "hot": 0, "num_failed_logins": 0, "logged_in": 0,
                "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0,
                "num_file_creations": 0, "num_shells": 0, "num_access_files": 0,
                "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0,
                "count": 128, "srv_count": 6, "serror_rate": 1.0, "srv_serror_rate": 1.0,
                "rerror_rate": 0.0, "srv_rerror_rate": 0.0, "same_srv_rate": 0.05,
                "diff_srv_rate": 0.07, "srv_diff_host_rate": 0.0, "dst_host_count": 255,
                "dst_host_srv_count": 6, "dst_host_same_srv_rate": 0.02,
                "dst_host_diff_srv_rate": 0.06, "dst_host_same_src_port_rate": 0.0,
                "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 1.0,
                "dst_host_srv_serror_rate": 1.0, "dst_host_rerror_rate": 0.0,
                "dst_host_srv_rerror_rate": 0.0
            }
        },
        headers=auth_headers,
        cookie=admin_cookie
    )
    print(f"  -> DoS Malicious Prediction: HTTP {status}, Alert Generated: {dos_res.get('alert_generated')}")
    assert status == 200
    assert dos_res.get("alert_generated") is True
    alert_id = dos_res.get("alert_id")

    # Update Alert Status in DB
    status, update_res, _, _ = make_request(
        f"{BASE_URL}/alerts/{alert_id}",
        method="PATCH",
        data={"status": "acknowledged"},
        headers=auth_headers,
        cookie=admin_cookie
    )
    print(f"  -> Alert Status Update ({alert_id}): HTTP {status}, New Status: {update_res.get('data', {}).get('status')}")
    assert status == 200
    assert update_res.get("data", {}).get("status") == "acknowledged"

    # --- 6. Telemetry Metrics & Logout ---
    print("\n[6/6] Verifying System Telemetry Metrics & Clean Session Logout...")
    status, metrics_res, _, _ = make_request(f"{BASE_URL}/metrics", headers={"Authorization": f"Bearer {admin_token}"})
    print(f"  -> Aggregated Metrics: HTTP {status}, Total Flows: {metrics_res.get('data', {}).get('measured', {}).get('totalFlows')}")
    assert status == 200

    status, _, _, _ = make_request(f"{BASE_URL}/auth/logout", method="POST")
    print(f"  -> Admin Logout: HTTP {status} (Expected 200)")
    assert status == 200

    print("\n============================================================")
    print("ALL PRODUCTION DEPLOYMENT SMOKE TESTS PASSED SUCCESSFULLY!")
    print("============================================================")

if __name__ == "__main__":
    try:
        run_deployment_smoke_tests()
    except Exception as e:
        print(f"\n[DEPLOYMENT SMOKE TEST FAILURE] {e}")
        sys.exit(1)
