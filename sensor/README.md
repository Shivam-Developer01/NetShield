# NetShield Network Sensor Microservice (`sensor/`)

The NetShield Network Sensor is a Python-based microservice that captures network traffic packets (via Scapy), aggregates packets into stateful 5-tuple bidirectional flows, extracts statistical flow features, maps flow statistics to raw dataset schemas (`NSL-KDD` and `CICIDS2017`), validates feature payloads, and delivers prediction requests to the Node.js backend API layer (`POST /api/predictions`).

---

## Component Architecture

```text
  Network Interface / PCAP File
               │
               ▼
  Packet Capture (liveCapture.py / pcapReader.py)
               │
               ▼
  5-Tuple Flow Aggregation (flowManager.py / flowKey.py)
               │
               ▼
  Base Feature Extraction (baseFeatures.py)
               │
               ▼
  Dataset Schema Mapping (nslKddFeatures.py / cicids2017Features.py)
               │
               ▼
  Feature Validation (featureValidator.py)
               │
               ▼
  HTTP Inference Client (mlClient.py)
               │
               ├──────────────────┐
               ▼                  ▼
     Node.js Backend       FastAPI ML Fallback
     (/api/predictions)       (/predict)
               │
               ├───────────────┐
               ▼               ▼
           MongoDB          Socket.IO
          (Log/Alert)      (React SOC UI)
```

---

## Quick Start & Usage

### 1. Installation
```bash
cd sensor
pip install -r requirements.txt
```

### 2. PCAP Replay Mode (Deterministic Testing)
```bash
python -m sensor.src.main --mode pcap --file sensor/samples/sample_test.pcap --dataset nsl_kdd
```

### 3. Live Capture Mode
> **Note**: Live capture on Windows requires Administrator privileges or Npcap driver installed.
```bash
python -m sensor.src.main --mode live --interface "Wi-Fi" --dataset cicids2017
```

---

## Configuration (`.env`)

| Variable | Default | Description |
|---|---|---|
| `SENSOR_MODE` | `pcap` | Capture mode: `pcap` or `live` |
| `SENSOR_INTERFACE` | `""` | Network interface name for live capture |
| `PCAP_FILE` | `sensor/samples/sample_test.pcap` | Path to input PCAP file |
| `DATASET_TYPE` | `nsl_kdd` | Target ML dataset schema (`nsl_kdd` or `cicids2017`) |
| `FLOW_TIMEOUT_SECONDS` | `30` | Inactive flow expiration timeout in seconds |
| `BACKEND_URL` | `http://localhost:5000` | Node.js Express backend service URL |
| `ML_SERVICE_URL` | `http://localhost:8000` | FastAPI ML service URL |
| `REQUEST_TIMEOUT_MS` | `5000` | HTTP request timeout in milliseconds |
| `MAX_ACTIVE_FLOWS` | `10000` | Active flow table memory limit |

---

## Test Execution

```bash
python -m pytest sensor/tests
```
