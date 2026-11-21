import requests

session = requests.Session()

# 1. First make a GET request to issue cookie
get_res = session.get('http://localhost:5000/api/health')
print("Cookies after GET /health:", session.cookies.get_dict())

# 2. Log in
login_res = session.post(
    'http://localhost:5000/api/auth/login',
    json={"email": "admin@netshield.local", "password": "AdminSecurePassword123!"}
)
login_data = login_res.json()
token = login_data['token']
print("Cookies after POST /login:", session.cookies.get_dict())
cookie_token = session.cookies.get('XSRF-TOKEN')
print("Using CSRF token:", cookie_token)

headers = {
    'Authorization': f'Bearer {token}',
    'x-xsrf-token': cookie_token
}

# 1. OLD MALFORMED SAMPLE
old_malformed_sample = {
    "Destination Port": 80,
    "Flow Duration": 5122111,
    "Total Fwd Packets": 3,
    "Total Backward Packets": 7,
    "Total Length of Fwd Packets": 26,
    "Total Length of Bwd Packets": 11607,
    "Fwd Packet Length Max": 20,
    "Fwd Packet Length Min": 0,
    "Fwd Packet Length Mean": 8.666666667,
    "Bwd Packet Length Max": 4344,
    "Bwd Packet Length Min": 0,
    "Bwd Packet Length Mean": 1658.142857,
    "Flow Bytes/s": 2270.938681,
    "Flow Packets/s": 1.952320049,
    "Flow IAT Mean": 569123.4444,
    "Flow IAT Std": 1704207.97,
    "Flow IAT Max": 5117942,
    "Flow IAT Min": 4,
    "Fwd IAT Total": 780,
    "Fwd IAT Mean": 390,
    "Fwd IAT Std": 547.3006486,
    "Fwd IAT Max": 777,
    "Fwd IAT Min": 3,
    "Bwd IAT Total": 5122066,
    "Bwd IAT Mean": 853677.6667,
    "Bwd IAT Std": 2088998.66,
    "Bwd IAT Max": 5117942,
    "Bwd IAT Min": 4,
    "Fwd PSH Flags": 0,
    "Bwd PSH Flags": 0,
    "Fwd URG Flags": 0,
    "Bwd URG Flags": 0,
    "Fwd Header Length": 72,
    "Bwd Header Length": 152,
    "Fwd Packets/s": 0.585696015,
    "Bwd Packets/s": 1.366624034,
    "Min Packet Length": 0,
    "Max Packet Length": 4344,
    "Packet Length Mean": 1057.545455,
    "Packet Length Std": 1653.498432,
    "Packet Length Variance": 2734057.069,
    "FIN Flag Count": 0,
    "SYN Flag Count": 0,
    "RST Flag Count": 0,
    "PSH Flag Count": 1,
    "ACK Flag Count": 0,
    "URG Flag Count": 0,
    "CWE Flag Count": 0,
    "ECE Flag Count": 0,
    "Down/Up Ratio": 2,
    "Average Packet Size": 1163.3,
    "Avg Fwd Segment Size": 8.666666667,
    "Avg Bwd Segment Size": 1658.142857,
    "Fwd Header Length.1": 72,
    "Fwd Avg Bytes/Bulk": 0,
    "Fwd Avg Packets/Bulk": 0,
    "Fwd Avg Bulk Rate": 0,
    "Bwd Avg Bytes/Bulk": 0,
    "Bwd Avg Packets/Bulk": 0,
    "Bwd Avg Bulk Rate": 0,
    "Subflow Fwd Packets": 3,
    "Subflow Fwd Bytes": 26,
    "Subflow Bwd Packets": 7,
    "Subflow Bwd Bytes": 11607,
    "Init_Win_bytes_forward": 8192,
    "Init_Win_bytes_backward": 229,
    "act_data_pkt_fwd": 2,
    "min_seg_size_forward": 20,
    "Active Mean": 0,
    "Active Std": 0,
    "Active Max": 0,
    "Active Min": 0,
    "Idle Mean": 0,
    "Idle Std": 0,
    "Idle Max": 0,
    "Idle Min": 0
}

# 2. AUTHENTIC SAMPLE
authentic_sample = {
    "Destination Port": 80,
    "Flow Duration": 1878,
    "Total Fwd Packets": 3,
    "Total Backward Packets": 6,
    "Total Length of Fwd Packets": 382,
    "Total Length of Bwd Packets": 11595,
    "Fwd Packet Length Max": 382,
    "Fwd Packet Length Min": 0,
    "Fwd Packet Length Mean": 127.333333,
    "Fwd Packet Length Std": 220.547803,
    "Bwd Packet Length Max": 4355,
    "Bwd Packet Length Min": 0,
    "Bwd Packet Length Mean": 1932.5,
    "Bwd Packet Length Std": 2182.468304,
    "Flow Bytes/s": 6377529.286,
    "Flow Packets/s": 4792.332268,
    "Flow IAT Mean": 234.75,
    "Flow IAT Std": 229.129876,
    "Flow IAT Max": 577,
    "Flow IAT Min": 15,
    "Fwd IAT Total": 975,
    "Fwd IAT Mean": 487.5,
    "Fwd IAT Std": 265.165043,
    "Fwd IAT Max": 675,
    "Fwd IAT Min": 300,
    "Bwd IAT Total": 1780,
    "Bwd IAT Mean": 356.0,
    "Bwd IAT Std": 399.788069,
    "Bwd IAT Max": 950,
    "Bwd IAT Min": 15,
    "Fwd PSH Flags": 0,
    "Bwd PSH Flags": 0,
    "Fwd URG Flags": 0,
    "Bwd URG Flags": 0,
    "Fwd Header Length": 104,
    "Bwd Header Length": 200,
    "Fwd Packets/s": 1597.444089,
    "Bwd Packets/s": 3194.888179,
    "Min Packet Length": 0,
    "Max Packet Length": 4355,
    "Packet Length Mean": 1197.7,
    "Packet Length Std": 1886.332364,
    "Packet Length Variance": 3558249.789,
    "FIN Flag Count": 0,
    "SYN Flag Count": 0,
    "RST Flag Count": 0,
    "PSH Flag Count": 1,
    "ACK Flag Count": 0,
    "URG Flag Count": 0,
    "CWE Flag Count": 0,
    "ECE Flag Count": 0,
    "Down/Up Ratio": 2,
    "Average Packet Size": 1330.777778,
    "Avg Fwd Segment Size": 127.333333,
    "Avg Bwd Segment Size": 1932.5,
    "Fwd Header Length.1": 104,
    "Fwd Avg Bytes/Bulk": 0,
    "Fwd Avg Packets/Bulk": 0,
    "Fwd Avg Bulk Rate": 0,
    "Bwd Avg Bytes/Bulk": 0,
    "Bwd Avg Packets/Bulk": 0,
    "Bwd Avg Bulk Rate": 0,
    "Subflow Fwd Packets": 3,
    "Subflow Fwd Bytes": 382,
    "Subflow Bwd Packets": 6,
    "Subflow Bwd Bytes": 11595,
    "Init_Win_bytes_forward": 29200,
    "Init_Win_bytes_backward": 235,
    "act_data_pkt_fwd": 1,
    "min_seg_size_forward": 32,
    "Active Mean": 0.0,
    "Active Std": 0.0,
    "Active Max": 0,
    "Active Min": 0,
    "Idle Mean": 0.0,
    "Idle Std": 0.0,
    "Idle Max": 0,
    "Idle Min": 0
}

def run_test(title, sample, ground_truth):
    payload = {
        "datasetType": "cicids2017",
        "inputData": sample,
        "sourceInfo": {"groundTruth": ground_truth}
    }
    res = session.post('http://localhost:5000/api/predictions', json=payload, headers=headers)
    print(f"\n==========================================")
    print(f"{title} (HTTP {res.status_code})")
    print(f"==========================================")
    if res.status_code != 200:
        print(f"Error: {res.text}")
        return
    data = res.json()
    pred = data['predictions'][0]
    print(f"Prediction:        {pred['prediction']}")
    print(f"Confidence:        {pred['confidence'] * 100:.2f}%")
    print(f"Alert Generated:   {data['alert_generated']}")
    print(f"Severity:          {data['severity']}")
    print(f"Model Version:     {data['model_version']}")
    print(f"Probabilities:")
    for k, v in pred['class_probabilities'].items():
        print(f"  - {k}: {v * 100:.4f}%")

run_test("1. PREVIOUS MALFORMED SAMPLE (SCREENSHOT REPRODUCTION)", old_malformed_sample, "DoS Hulk")
run_test("2. AUTHENTIC CICIDS2017 SAMPLE (ROW 74860)", authentic_sample, "DoS Hulk")
