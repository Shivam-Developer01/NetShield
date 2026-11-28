# NetShield: AI-Powered Network Intrusion Detection System (NIDS)

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-339933?logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Express.js](https://img.shields.io/badge/Express.js-4.21-000000?logo=express&logoColor=white)](https://expressjs.com/)
[![React](https://img.shields.io/badge/React-18.3-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![MongoDB](https://img.shields.io/badge/MongoDB-7.0-47A248?logo=mongodb&logoColor=white)](https://www.mongodb.com/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)

NetShield is a production-structured, end-to-end AI-powered Network Intrusion Detection System (NIDS) and Security Operations Center (SOC) dashboard. The system captures or replays network flows, extracts statistical flow features, performs high-throughput machine learning inference via a dedicated microservice, correlates security incidents in real time, and broadcasts alerts over WebSockets to an interactive monitoring dashboard.

> [!IMPORTANT]
> **Operational Mode:** The network sensor in this repository operates strictly in **detection and monitoring mode**. It sniffs network traffic or reads PCAP capture files, analyzes flow statistics, and dispatches prediction requests and alerts to the SOC. It does **not** automatically inject packet drops, modify firewall tables, or block network traffic at the kernel or network interface level unless an active firewall remediation module is explicitly connected.

---

## Table of Contents

1. [Project Overview & System Architecture](#1-project-overview--system-architecture)
2. [Complete Repository Structure](#2-complete-repository-structure)
3. [Prerequisites](#3-prerequisites)
4. [Dataset Installation and Configuration](#4-dataset-installation-and-configuration)
5. [Environment & Credentials Configuration](#5-environment--credentials-configuration)
6. [Data Preprocessing Pipeline](#6-data-preprocessing-pipeline)
7. [Model Training & Evaluation](#7-model-training--evaluation)
8. [Production Model Artifacts & Safety Rules](#8-production-model-artifacts--safety-rules)
9. [Running NetShield](#9-running-netshield)
   - [Option A: Docker Compose (Recommended)](#option-a-docker-compose-recommended)
   - [Option B: Running Services Locally](#option-b-running-services-locally)
10. [Network Sensor Configuration](#10-network-sensor-configuration)
11. [API Documentation](#11-api-documentation)
12. [Developer Contribution & Workflow Guide](#12-developer-contribution--workflow-guide)
13. [Troubleshooting Guide](#13-troubleshooting-guide)
14. [Security & Compliance Considerations](#14-security--compliance-considerations)

---

## 1. Project Overview & System Architecture

NetShield addresses the challenge of identifying sophisticated network attacks in real time while minimizing false positive rates and eliminating machine learning data leakage.

### Key Capabilities
- **Leakage-Free Dual Benchmark Models**: Implements separate preprocessing, feature selection, and inference pipelines for both **NSL-KDD** (5-class taxonomy) and **CICIDS2017** (15-class taxonomy).
- **Two-Stage Cascade & Expert Ensembles**: Employs cost-sensitive XGBoost classifiers with dedicated binary specialist models for rare attack vectors (e.g., R2L, U2R) and dynamic threshold routing.
- **Decoupled Microservice Architecture**: Strict separation of concerns across a Python FastAPI ML inference service, a Node.js/Express orchestration backend, a React SOC dashboard, a Python network sensor, and a MongoDB persistence store.
- **Real-Time SOC Alerting**: Automated mapping of raw inference results to standard security severities (`low`, `medium`, `high`, `critical`), real-time WebSocket push notifications to analysts, and SMTP digest alerting.
- **Enterprise Security Hardening**: Dual-token authentication (HTTP-only JWT cookies + Bearer tokens for internal microservices), double-submit cookie CSRF protection, rate limiting, and Role-Based Access Control (`ADMIN`, `ANALYST`, `VIEWER`, `SERVICE`).

### High-Level Architecture Diagram

```mermaid
flowchart TD
    subgraph DataPlane["Data Collection & Sensor"]
        PCAP["PCAP Dump / Live Interface"] --> SENSOR["Python Network Sensor\n(Scapy Flow Engine)"]
    end

    subgraph MLPlane["Machine Learning Subsystem"]
        FASTAPI["FastAPI ML Service\n(:8000)"]
        FROZEN["Frozen Production Artifacts\nv1.3 (NSL-KDD) / v1.2 (CICIDS2017)"]
        FROZEN --> FASTAPI
    end

    subgraph BackendPlane["Application & Persistence"]
        BACKEND["Node.js / Express Backend\n(:5000)"]
        MONGO[("MongoDB 7.0\n(:27017)")]
        BACKEND <--> MONGO
    end

    subgraph FrontendPlane["Analyst Presentation"]
        FRONTEND["React SOC Dashboard\n(Vite/Nginx :8080 or :5173)"]
    end

    SENSOR -- "1. Flow Features (POST /api/predictions)\n[X-Service-Token]" --> BACKEND
    BACKEND -- "2. Inference Request (POST /predict)" --> FASTAPI
    FASTAPI -- "3. Probabilities & Attack Classes" --> BACKEND
    BACKEND -- "4. Store Log & Threat Alert" --> MONGO
    BACKEND -- "5. WebSocket Broadcast (alert:created)" --> FRONTEND
    FRONTEND -- "REST API (Auth, Investigations, Analytics)" --> BACKEND
```

### End-to-End Prediction & Alert Lifecycle

```mermaid
sequenceDiagram
    autonumber
    participant Sensor as Python Sensor / Client
    participant Backend as Node.js Backend (:5000)
    participant FastAPI as FastAPI ML Engine (:8000)
    participant DB as MongoDB (:27017)
    participant Frontend as React Dashboard (:8080)

    Sensor->>Backend: POST /api/predictions (datasetType, inputData, sourceInfo)
    Note over Sensor,Backend: Auth: X-Service-Token or Bearer JWT
    Backend->>FastAPI: POST /predict (dataset_type, input_data)
    Note over FastAPI: Preprocessor -> Feature Selector -> Model -> Label Decoder
    FastAPI-->>Backend: Return predictions, probabilities, latency
    Backend->>DB: Save Log document (raw prediction & network metadata)
    alt Prediction is an Attack (Non-Normal / Non-BENIGN)
        Backend->>Backend: Map Attack Class & Confidence to Severity Policy
        Backend->>DB: Save Alert document & Trigger Incident Correlation
        Backend-->>Frontend: Emit WebSocket event 'alert:created' & 'metrics:updated'
    end
    Backend-->>Sensor: Return 201 Created with prediction summary
    Frontend->>Frontend: Dynamic update of KPI cards, threat charts, & alert feeds
```

---

## 2. Complete Repository Structure

```
NetShield/
├── .github/
│   └── workflows/
│       └── ci.yml                     # GitHub Actions CI verification pipeline
├── artifacts/                         # Serialized ML pipeline models and metadata
│   ├── encoders/                      # Trained LabelEncoder artifacts (.joblib)
│   ├── features/                      # Selected feature schemas (.json) & selectors (.joblib)
│   ├── metadata/                      # Evaluation metrics, training configs, split summaries
│   ├── models/
│   │   ├── baseline/                  # Baseline models (Logistic Regression, Decision Tree, Naive Bayes)
│   │   └── ensemble/                  # Ensemble models (Random Forest, LightGBM, XGBoost)
│   ├── preprocessors/                 # Fitted ColumnTransformers (StandardScaler, OneHotEncoder)
│   ├── production/                    # Bundled fallback production artifacts
│   │   ├── cicids2017/                # Base production bundle for CICIDS2017
│   │   └── nsl_kdd/                   # Base production bundle for NSL-KDD
│   ├── remediated/                    # Leakage-remediated benchmark models & metadata
│   │   ├── cicids2017/                # Chronological block-split remediated model (v1.1)
│   │   └── nsl_kdd/                   # Leakage-safe evaluated NSL-KDD model artifacts
│   ├── v1.2/
│   │   └── cicids2017/                # Active Production Bundle: Two-Stage Cascade Model
│   └── v1.3/
│       └── nsl_kdd/                   # Active Production Bundle: Expert Ensemble + Specialists
├── backend/                           # Node.js + Express + MongoDB Backend Microservice
│   ├── src/
│   │   ├── config/                    # Database (Mongoose) and environment settings
│   │   ├── controllers/               # Route handlers (auth, predictions, alerts, analytics, settings)
│   │   ├── middleware/                # Auth (JWT), RBAC, CSRF, rate limiter, error handling
│   │   ├── models/                    # Mongoose schemas (User, Alert, Log, Incident, Setting, Telemetry)
│   │   ├── realtime/                  # Socket.IO WebSocket server and event publishers
│   │   ├── routes/                    # Express modular route definitions
│   │   ├── scripts/                   # Administrative tasks (seedAdmin.js)
│   │   ├── services/                  # Business logic, correlation engine, ML client, notifications
│   │   ├── utils/                     # Audit logger, severity mapper, metrics collector
│   │   └── validators/                # Zod request payload validation schemas
│   ├── tests/                         # Jest backend unit and integration test suites
│   ├── Dockerfile                     # Production Node.js multi-stage container build
│   ├── package.json                   # Backend dependencies and test scripts
│   └── .env.example                   # Backend environment template
├── data/                              # Dataset storage (Ignored by Git except documentation)
│   ├── raw/                           # Original, untouched NSL-KDD (.txt) and CICIDS2017 (.csv)
│   ├── processed/                     # Leakage-free preprocessed compressed arrays (.npz)
│   │   ├── cicids2017/                # Processed train/test .npz for CICIDS2017
│   │   └── nsl_kdd/                   # Processed train/test .npz for NSL-KDD
│   └── external/                      # Reference mappings and attack taxonomy dictionaries
├── docs/                              # Architecture decision records, model cards, audit reports
├── frontend/                          # React 18 + Vite SOC Dashboard Application
│   ├── src/
│   │   ├── auth/                      # AuthContext and ProtectedRoute guards
│   │   ├── components/                # Modular UI widgets, KPI cards, tables, layout navigation
│   │   ├── pages/                     # Dashboard, Alerts, Predictions, Analytics, Operations, Settings
│   │   ├── services/                  # Axios HTTP client (CSRF-intercepted) and Socket.IO client
│   │   └── __tests__/                 # Vitest frontend unit and integration test suites
│   ├── Dockerfile                     # Multi-stage container build (Node build -> Nginx alpine)
│   ├── nginx.conf                     # Production Nginx reverse proxy routing
│   ├── package.json                   # Frontend dependencies and Vite build scripts
│   └── .env.example                   # Frontend environment template
├── ml_service/                        # FastAPI Machine Learning Microservice
│   ├── audits/                        # Data leakage, split sanity, and reproducibility audit scripts
│   ├── benchmarks/                    # Latency and throughput benchmarking scripts
│   ├── src/
│   │   ├── analysis/                  # Exploratory dataset distribution and class balance tools
│   │   ├── api/                       # FastAPI application, route declarations, Pydantic schemas
│   │   ├── features/                  # Feature selection algorithms (MI, Correlation, RF Importance)
│   │   ├── inference/                 # Core InferencePipeline (loads v1.3 and v1.2 frozen bundles)
│   │   ├── models/                    # Training routines for baseline and ensemble classifiers
│   │   ├── preprocessing/             # Preprocessors (NSLKDDPreprocessor, CICIDS2017Preprocessor)
│   │   └── production/                # Production artifact packager and verification utilities
│   ├── tests/                         # Pytest suites for preprocessing, models, API, and inference
│   ├── training/                      # Authoritative advanced training pipelines (Two-Stage & Expert Ensembles)
│   │   ├── cicids2017/                # 5-step pipeline generating v1.2 Two-Stage Cascade
│   │   └── nsl_kdd/                   # 10-step research pipeline generating v1.3 Expert Ensemble
│   ├── Dockerfile                     # Production Python FastAPI container build
│   ├── requirements.txt               # Pinned Python dependencies for ML service
│   ├── run_server.py                  # Standalone microservice entry point
│   └── .env.example                   # ML service environment template
├── scripts/                           # Cross-system administrative and verification utilities
│   ├── backup_mongodb.py              # Automated MongoDB BSON dump and gzip backup utility
│   ├── test_backup_restore.js         # Integration test for database backup verification
│   ├── test_csrf_security.js          # Security audit script for CSRF protection
│   ├── test_e2e_soc_flow.py           # Full end-to-end SOC pipeline test
│   └── verify_deployment.py           # Production deployment smoke test suite
├── sensor/                            # Python Network Sensor Microservice
│   ├── samples/                       # Sample capture files (sample_test.pcap)
│   ├── scripts/                       # Sample generators and DoS simulation tools
│   ├── src/
│   │   ├── capture/                   # Scapy PCAP reader and Live interface capture handlers
│   │   ├── config/                    # Pydantic sensor configuration loader
│   │   ├── features/                  # Flow-to-feature mappers for NSL-KDD and CICIDS2017
│   │   ├── flow/                      # Bidirectional flow tracker and timeout flush manager
│   │   ├── inference/                 # Resilient HTTP client with retry and service-token auth
│   │   ├── models/                    # Internal NetworkFlow state data structures
│   │   └── main.py                    # Sensor CLI daemon entry point
│   ├── tests/                         # Pytest suites for packet parsing, flow tracking, feature mapping
│   ├── Dockerfile                     # Sensor container build
│   ├── requirements.txt               # Python dependencies for network capture
│   └── .env.example                   # Sensor environment template
├── docker-compose.yml                 # Multi-container orchestration specification
├── .env.example                       # Root environment variable template for Docker Compose
└── .gitignore                         # Git exclusion rules (virtualenvs, raw data, node_modules)
```

### Explanations of Special Directories

#### `artifacts/remediated/`
During the lifecycle of NetShield (documented in `docs/ml-integrity-remediation-report.md`), an ML integrity audit revealed that standard random row-shuffling across CICIDS2017 PCAP files caused synthetic data leakage between train and test sets.
- **Purpose**: Contains the leakage-remediated models trained on strict chronological sub-capture block splits (70% train, 15% validation, 15% test).
- **Usage**: Developers do not need to place files here manually. This directory stores verified audit baselines (`artifacts/remediated/cicids2017/` and `artifacts/remediated/nsl_kdd/`). If you research new leakage-resistant splitting algorithms, store your comparison models here.

#### `node_modules/` (`backend/node_modules/` and `frontend/node_modules/`)
- Both backend and frontend manage separate JavaScript dependencies.
- **Never commit `node_modules/` to Git**; they are strictly excluded in `.gitignore`.
- Developers must install dependencies in their respective directories using the package managers:
  - Backend: `cd backend && npm ci` (or `npm install`)
  - Frontend: `cd frontend && npm ci` (or `npm install`)

#### `data/raw/`
- Contains untouched, original benchmark datasets.
- Original files must remain strictly unmodified to ensure reproducible preprocessing.
- Detailed file placement instructions are covered in [Section 4](#4-dataset-installation-and-configuration).

#### `data/processed/`
- Stores compressed NumPy archives (`.npz`) produced by the preprocessing scripts.
- Contains transformed float32 feature matrices ($X$) and encoded labels ($y$) ready for model training:
  - `data/processed/nsl_kdd/train_processed.npz` & `test_processed.npz`
  - `data/processed/cicids2017/train_processed.npz` & `test_processed.npz`
- Feature-reduced datasets (`train_reduced.npz`, `test_reduced.npz`) are generated during feature selection.

---

## 3. Prerequisites

Ensure your host machine meets the following requirements before installation:

| Tool | Recommended Version | Minimum Version | Notes |
| :--- | :--- | :--- | :--- |
| **Git** | `2.40+` | `2.25+` | Required to clone and version the codebase |
| **Python** | `3.10` – `3.12` | `3.10` | Used for ML service, training, and sensor |
| **Node.js** | `18.x` or `20.x` LTS | `18.0.0` | Required for backend and frontend build |
| **npm** | `9.x` or `10.x` | `8.0.0` | Bundled with Node.js |
| **Docker Desktop** | `24.x+` (Compose v2) | `20.10+` | Recommended execution approach |
| **MongoDB** | `7.0` | `6.0` | Required only if running locally without Docker |
| **Npcap / libpcap** | Latest | N/A | Windows only: Required **only** for sensor live interface capture |

---

## 4. Dataset Installation and Configuration

NetShield models are trained on two standard intrusion detection benchmarks: **NSL-KDD** and **CICIDS2017**. Because raw benchmark datasets are large and subject to institutional licensing, they are not stored in Git.

### 1. NSL-KDD Dataset
- **Provider**: University of New Brunswick (UNB) / Canadian Institute for Cybersecurity
- **Required Files**:
  1. `KDDTrain+.txt` (125,973 records)
  2. `KDDTest+.txt` (22,544 records)
- **Destination**: Place both files directly into: `data/raw/`
- **Naming Rule**: Must match `KDDTrain+.txt` and `KDDTest+.txt` exactly (case-sensitive).

### 2. CICIDS2017 Dataset
- **Provider**: Canadian Institute for Cybersecurity (CIC)
- **Required Files**: Exactly 8 CSV files representing the daily network traffic captures:
  1. `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`
  2. `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
  3. `Friday-WorkingHours-Morning.pcap_ISCX.csv`
  4. `Monday-WorkingHours.pcap_ISCX.csv`
  5. `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`
  6. `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`
  7. `Tuesday-WorkingHours.pcap_ISCX.csv`
  8. `Wednesday-workingHours.pcap_ISCX.csv`
- **Destination**: Place all 8 CSV files directly into: `data/raw/`
- **Naming Rule**: Note the exact casing used in the UNB release (e.g., `Infilteration` with an `e`, lowercase `workingHours` on Wednesday).

### Expected Directory Layout

```
data/
├── raw/
│   ├── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
│   ├── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
│   ├── Friday-WorkingHours-Morning.pcap_ISCX.csv
│   ├── Monday-WorkingHours.pcap_ISCX.csv
│   ├── Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
│   ├── Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
│   ├── Tuesday-WorkingHours.pcap_ISCX.csv
│   ├── Wednesday-workingHours.pcap_ISCX.csv
│   ├── KDDTest+.txt
│   ├── KDDTrain+.txt
│   └── README.md
├── processed/
│   ├── cicids2017/
│   └── nsl_kdd/
└── external/
```

### Verifying Dataset Placement

Run the following command from the project root to verify all 10 dataset files:

#### Windows (PowerShell)
```powershell
$expected = @(
  "KDDTrain+.txt", "KDDTest+.txt",
  "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
  "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
  "Friday-WorkingHours-Morning.pcap_ISCX.csv",
  "Monday-WorkingHours.pcap_ISCX.csv",
  "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
  "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
  "Tuesday-WorkingHours.pcap_ISCX.csv",
  "Wednesday-workingHours.pcap_ISCX.csv"
)
foreach ($f in $expected) {
  $p = Join-Path "data/raw" $f
  if (Test-Path $p) { Write-Host "[OK] Found $f" -ForegroundColor Green }
  else { Write-Host "[MISSING] $f" -ForegroundColor Red }
}
```

#### Linux / macOS (Bash)
```bash
expected=(
  "KDDTrain+.txt" "KDDTest+.txt"
  "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
  "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
  "Friday-WorkingHours-Morning.pcap_ISCX.csv"
  "Monday-WorkingHours.pcap_ISCX.csv"
  "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"
  "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
  "Tuesday-WorkingHours.pcap_ISCX.csv"
  "Wednesday-workingHours.pcap_ISCX.csv"
)
for f in "${expected[@]}"; do
  if [ -f "data/raw/$f" ]; then
    echo "[OK] Found $f"
  else
    echo "[MISSING] $f"
  fi
done
```

---

## 5. Environment & Credentials Configuration

NetShield uses `.env` files for configuration. Templates with sensible defaults (`.env.example`) are provided across the repository.

> [!CAUTION]
> **Never commit `.env` files to source control.** All `.env` files are ignored in `.gitignore`. Use unique passwords and strong secret keys in production environments.

### Environment Files Location Guide

| Service | Environment File Location | Required By | Description |
| :--- | :--- | :--- | :--- |
| **Docker Compose** | `.env` (Project Root) | Docker Compose | Sets MongoDB credentials, ports, and JWT secret across containers |
| **Backend** | `backend/.env` | Local Node.js Backend | Configures MongoDB connection, JWT secret, admin credentials, SMTP |
| **Frontend** | `frontend/.env` | Local Vite Dev Server | Configures `VITE_API_BASE_URL` (consumed during build/dev) |
| **ML Service** | `ml_service/.env` | Local FastAPI Service | Configures host, port, workers, and CORS origins |
| **Sensor** | `sensor/.env` | Local Sensor CLI | Configures capture mode, PCAP file, dataset type, and auth token |

---

### Master Environment Variable Reference

#### 1. Root Docker Compose Configuration (`.env`)
Create `.env` in the project root:
```ini
# --- MongoDB Configuration ---
MONGO_INITDB_ROOT_USERNAME=netshield_admin
MONGO_INITDB_ROOT_PASSWORD=SuperSecretMongoPassword2026!
MONGODB_URI=mongodb://netshield_admin:SuperSecretMongoPassword2026!@mongodb:27017/netshield_db?authSource=admin

# --- Backend Service ---
PORT=5000
NODE_ENV=production
LOG_LEVEL=info
JWT_SECRET=replace_with_a_secure_random_64_character_string_for_jwt
JWT_EXPIRES_IN=1h
COOKIE_NAME=netshield_token
CORS_ORIGINS=http://localhost:8080,http://127.0.0.1:8080,http://localhost:5000,http://frontend:5173

# --- Inter-Service Communication ---
ML_SERVICE_URL=http://ml-service:8000
ML_SERVICE_TIMEOUT_MS=10000
SENSOR_SERVICE_TOKEN=replace_with_secure_random_service_token_2026

# --- Rate Limiting ---
AUTH_RATE_LIMIT_WINDOW_MS=900000
AUTH_RATE_LIMIT_MAX=10

# --- Default Admin Seeding ---
ADMIN_EMAIL=admin@netshield.local
ADMIN_PASSWORD=AdminSecurePassword123!
ADMIN_USERNAME=sysadmin

# --- SMTP Alert Notifications (Optional) ---
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=
SMTP_PASS=
SMTP_FROM=
```

#### 2. Backend Local Configuration (`backend/.env`)
For running the backend locally against a local MongoDB instance:
```ini
PORT=5000
NODE_ENV=development
LOG_LEVEL=info

# Connect to local MongoDB instance
MONGODB_URI=mongodb://localhost:27017/netshield_db

# ML Service endpoint (running on localhost)
ML_SERVICE_URL=http://127.0.0.1:8000
ML_SERVICE_TIMEOUT_MS=10000

# CORS Origins for local development
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173,http://localhost:8080

# Authentication & Tokens
JWT_SECRET=dev_jwt_secret_change_me_in_production
JWT_EXPIRES_IN=1h
COOKIE_NAME=netshield_token
SENSOR_SERVICE_TOKEN=dev_sensor_service_token_secure_2026

# Admin Seeding
ADMIN_EMAIL=admin@netshield.local
ADMIN_PASSWORD=AdminSecurePassword123!
ADMIN_USERNAME=sysadmin

# Optional SMTP Settings
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=
SMTP_PASS=
SMTP_FROM=
```

#### 3. Frontend Local Configuration (`frontend/.env`)
```ini
# Points to the Node.js backend API
VITE_API_BASE_URL=http://localhost:5000/api
```

#### 4. ML Service Local Configuration (`ml_service/.env`)
```ini
HOST=0.0.0.0
PORT=8000
WORKERS=1
LOG_LEVEL=info
CORS_ORIGINS=http://localhost:5000,http://localhost:5173,http://127.0.0.1:5000,http://127.0.0.1:5173
```

#### 5. Sensor Local Configuration (`sensor/.env`)
```ini
SENSOR_MODE=pcap
SENSOR_INTERFACE=
PCAP_FILE=sensor/samples/sample_test.pcap
DATASET_TYPE=nsl_kdd
FLOW_TIMEOUT_SECONDS=30
BACKEND_URL=http://localhost:5000
ML_SERVICE_URL=http://localhost:8000
SENSOR_SERVICE_TOKEN=dev_sensor_service_token_secure_2026
REQUEST_TIMEOUT_MS=5000
BATCH_SIZE=1
MAX_ACTIVE_FLOWS=10000
MAX_PACKET_SIZE=65535
MAX_QUEUE_SIZE=50000
LOG_LEVEL=INFO
```

---

## 6. Data Preprocessing Pipeline

Preprocessing converts raw CSVs and text files into normalized, leakage-free feature representations with float32 optimization.

### Preprocessing Specifications

| Dataset | Preprocessing Script | Input Files | Output Processed Files | Output Artifacts |
| :--- | :--- | :--- | :--- | :--- |
| **NSL-KDD** | `ml_service/src/preprocessing/run_preprocessing.py` | `data/raw/KDDTrain+.txt`, `data/raw/KDDTest+.txt` | `data/processed/nsl_kdd/train_processed.npz`, `test_processed.npz` | `artifacts/preprocessors/nsl_kdd_preprocessor.joblib`, `artifacts/encoders/nsl_kdd_label_encoder.joblib`, `artifacts/features/nsl_kdd_features.json` |
| **CICIDS2017** | `ml_service/src/preprocessing/run_preprocessing.py` | 8 raw CSV files in `data/raw/` | `data/processed/cicids2017/train_processed.npz`, `test_processed.npz` | `artifacts/preprocessors/cicids2017_preprocessor.joblib`, `artifacts/encoders/cicids2017_label_encoder.joblib`, `artifacts/features/cicids2017_features.json` |

### Key Preprocessing Steps Enforced by Code:
1. **Zero Data Leakage**: The `ColumnTransformer` is fitted **strictly** on the training set (`KDDTrain+` or the 80% stratified train split of CICIDS2017). The test set is only transformed using the pre-fitted transformer.
2. **Numeric Downcasting**: All numeric features are downcasted to `float32` (saving ~50% RAM to ensure smooth execution on an 8GB RAM development machine).
3. **Constant Feature Removal**: 8 zero-variance constant features identified in CICIDS2017 (e.g., `Bwd PSH Flags`, `Fwd Avg Bytes/Bulk`) are automatically dropped.
4. **Clean Infinity / NaN Values**: In CICIDS2017, $+\infty$ and $-\infty$ flow rates are converted to `np.nan` and imputed with median values learned on the training set.
5. **Class Taxonomy Mapping**:
   - NSL-KDD: Mapped from individual attack labels to 5 canonical categories: `Normal`, `DoS`, `Probe`, `R2L`, `U2R`.
   - CICIDS2017: Strips whitespace and normalizes to 15 attack classes (e.g., `BENIGN`, `DDoS`, `PortScan`, `Bot`, `Infiltration`, `Web Attack Brute Force`).

### Executing Preprocessing

Run the master preprocessing script from the project root:

#### Windows (PowerShell / CMD)
```powershell
# Ensure virtual environment is activated
python ml_service/src/preprocessing/run_preprocessing.py
```

#### Linux / macOS
```bash
python3 ml_service/src/preprocessing/run_preprocessing.py
```

### Feature Selection Step

Following preprocessing, feature selection eliminates multi-collinear features and selects optimal features via Mutual Information and Random Forest importance:

```bash
# Execute from project root
python ml_service/src/features/run_feature_selection.py
```
This generates:
- `data/processed/nsl_kdd/train_reduced.npz` & `test_reduced.npz`
- `data/processed/cicids2017/train_reduced.npz` & `test_reduced.npz`
- Feature selector objects in `artifacts/features/`

---

## 7. Model Training & Evaluation

NetShield provides training scripts for baseline classifiers, ensemble models, and the specialized production architectures.

### 1. Training Baseline Models
Trains and evaluates Logistic Regression, Decision Tree, and Gaussian Naive Bayes:
```bash
python ml_service/src/models/train_baseline_models.py
```
*Outputs saved to `artifacts/models/baseline/` and metadata logged in `artifacts/metadata/baseline_models_metadata.json`.*

### 2. Training Advanced Ensemble Models
Performs hyperparameter search (`RandomizedSearchCV`) and evaluates Random Forest, LightGBM, and XGBoost:
```bash
python ml_service/src/models/train_ensemble_models.py
```
*Outputs saved to `artifacts/models/ensemble/` and evaluation results recorded in `artifacts/metadata/`.*

### 3. Authoritative Production Pipelines

To replicate or experiment with the active production models, navigate to the dataset training directories in `ml_service/training/`:

#### A. CICIDS2017 Two-Stage Cascade Model (`v1.2`)
The two-stage cascade uses a Stage 1 cost-sensitive binary detector tuned to minimize false negatives on high-volume attacks followed by a Stage 2 multiclass routing classifier.
```bash
# Run the complete sequence from project root
python ml_service/training/cicids2017/01_investigate_false_negatives.py
python ml_service/training/cicids2017/02_train_and_tune_twostage_models.py
python ml_service/training/cicids2017/03_train_and_evaluate_v1_2.py
python ml_service/training/cicids2017/04_sensor_stress_test_v1_2.py
python ml_service/training/cicids2017/05_test_end_to_end.py
```

#### B. NSL-KDD Expert Ensemble Model (`v1.3`)
Combines a base 5-class XGBoost classifier with dedicated specialist models for rare attack classes (`R2L` and `U2R`), 14 derived network features, and dynamic uncertainty routing:
```bash
# Run the pipeline from project root
python ml_service/training/nsl_kdd/01_nsl_data_audit.py
python ml_service/training/nsl_kdd/02_leakage_safe_experiments.py
python ml_service/training/nsl_kdd/03_attack_holdout_experiment.py
python ml_service/training/nsl_kdd/04_feature_ablation_and_tuning.py
python ml_service/training/nsl_kdd/05_check_r2l_test_features.py
python ml_service/training/nsl_kdd/06_train_and_evaluate_v1_3.py
python ml_service/training/nsl_kdd/07_expert_ensemble_experiments.py
python ml_service/training/nsl_kdd/08_test_expert_ensemble_v1_3.py
python ml_service/training/nsl_kdd/09_package_and_verify_v1_3.py
python ml_service/training/nsl_kdd/10_audit_v1_3_consistency.py
```

---

## 8. Production Model Artifacts & Safety Rules

> [!CAUTION]
> **Production Model Protection Rule:** The repository contains verified, frozen production model bundles. **Do not delete, overwrite, retrain, or rename the files in `artifacts/v1.3/nsl_kdd/`, `artifacts/v1.2/cicids2017/`, or `artifacts/production/`.**

### Active Production Model Inventory

The FastAPI ML Service (`ml_service/src/inference/pipeline.py`) automatically prioritizes loading from the verified versioned directories:

#### 1. NSL-KDD Production Bundle: `artifacts/v1.3/nsl_kdd/`
- **Architecture**: Expert Ensemble v1.3 (Base 5-class XGBoost + R2L Specialist + U2R Specialist + Uncertainty Router)
- **Features**: 37 base features + 14 real-time derived features
- **Files**:
  - `best_model.joblib`: Serialized `NetShieldNSLKDDExpertEnsembleV13` container
  - `preprocessor.joblib`: Fitted `ColumnTransformer`
  - `feature_selector.joblib`: Feature selector (`IdentitySelector`)
  - `label_encoder.joblib`: 5-class `LabelEncoder` (`Normal`, `DoS`, `Probe`, `R2L`, `U2R`)
  - `feature_schema.json`: Expected input schema
  - `metadata.json`: Empirical evaluation metrics
  - `checksums.sha256`: Cryptographic integrity hashes
- **Empirical Metrics**:
  - Test Accuracy: `77.28%` (evaluated on canonical `KDDTest+` containing 17 unseen zero-day attacks)
  - Normal Class F1-Score: `90.28%`
  - Probe F1-Score: `79.93%`
  - R2L F1-Score: `68.47%`

#### 2. CICIDS2017 Production Bundle: `artifacts/v1.2/cicids2017/`
- **Architecture**: Two-Stage Cascade v1.2 (Stage 1 Binary Attack Filter + Stage 2 Multiclass Routing)
- **Features**: 43 selected flow features
- **Files**:
  - `best_model.joblib`: Serialized cascade classifier
  - `preprocessor.joblib`: Fitted `ColumnTransformer` with float32 scaling
  - `feature_selector.joblib`: 43-feature selector object
  - `label_encoder.joblib`: 15-class `LabelEncoder`
  - `feature_schema.json`: Expected input schema
  - `metadata.json`: Empirical evaluation metrics
- **Empirical Metrics**:
  - Test Accuracy: `99.87%`
  - Weighted F1-Score: `99.87%`
  - DDoS / DoS Hulk F1-Score: `> 99.8%`
  - PortScan F1-Score: `99.66%`
  - Macro False Positive Rate (FPR): `0.0187%`

### Safe Experimental Training Workflow
If you want to train an experimental model:
1. Save your experimental outputs into a separate directory (e.g., `artifacts/experiments/my_new_model/`).
2. Do not modify `artifacts/v1.3/` or `artifacts/v1.2/`.
3. To test your experimental model without disrupting production, configure a test runner script pointing to your experimental artifact directory.

---

## 9. Running NetShield

### Option A: Docker Compose (Recommended)

Docker Compose builds and coordinates all 5 microservices in isolated bridge networking with persistent MongoDB storage.

#### 1. Prepare Environment
Copy `.env.example` in the project root to `.env`:
```powershell
# Windows PowerShell
Copy-Item .env.example .env
```
```bash
# Linux / macOS
cp .env.example .env
```

#### 2. Build and Launch Containers
```bash
# Build all service images
docker compose build

# Start services in detached mode
docker compose up -d
```

#### 3. Service Inventory & Port Mappings

| Service Name | Container Name | Host Port | Container Port | Purpose | Health Check |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **mongodb** | `netshield-mongodb` | Internal | `27017` | MongoDB 7.0 persistence store | `mongosh ping` |
| **ml-service** | `netshield-ml-service` | `8000` | `8000` | FastAPI ML inference engine | `GET /health` |
| **backend** | `netshield-backend` | `5000` | `5000` | Node.js Express REST & WebSockets | `GET /health` |
| **frontend** | `netshield-frontend` | **`8080`** | `5173` | React SOC Dashboard (Nginx) | `wget /` |
| **sensor** | `netshield-sensor` | Internal | N/A | Scapy PCAP replayer & flow daemon | Process state |

> [!NOTE]
> Notice the frontend port mapping: **`http://localhost:8080`** maps to container port `5173`. Access the dashboard in your browser via `http://localhost:8080`.

#### 4. Managing Docker Services
```bash
# View running container status
docker compose ps

# View unified logs
docker compose logs -f

# View logs for a single service
docker compose logs -f backend
docker compose logs -f ml-service
docker compose logs -f sensor

# Restart a specific service
docker compose restart backend

# Stop all services safely (Preserves MongoDB volume)
docker compose down
```

> [!CAUTION]
> Avoid running `docker compose down -v` unless you intentionally want to delete all stored MongoDB logs, alerts, users, and settings.

#### 5. Verify Container Health
Run the automated verification script from your host:
```bash
python scripts/verify_deployment.py
```

---

### Option B: Running Services Locally

To develop or debug individual services, run each component locally on your host machine.

#### Step 1: Start MongoDB
Start a local MongoDB daemon listening on `localhost:27017`:
```bash
# Verify MongoDB is running
mongosh --eval "db.runCommand('ping').ok"
```

#### Step 2: Setup Python Virtual Environment
From the project root:
```powershell
# Windows
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r ml_service/requirements.txt
pip install -r sensor/requirements.txt
```
```bash
# Linux / macOS
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r ml_service/requirements.txt
pip install -r sensor/requirements.txt
```

#### Step 3: Run FastAPI ML Service
```bash
# Working directory: Project Root
# Terminal 1:
python ml_service/run_server.py
```
*Runs on `http://127.0.0.1:8000`. Verify by opening OpenAPI docs at `http://127.0.0.1:8000/docs`.*

#### Step 4: Run Node.js Backend Service
```bash
# Terminal 2:
cd backend
npm install
cp .env.example .env

# Seed the default administrative user into MongoDB
npm run seed:admin

# Start development server with live reload
npm run dev
```
*Runs on `http://127.0.0.1:5000`. Health check: `http://127.0.0.1:5000/health`.*

#### Step 5: Run React Frontend Service
```bash
# Terminal 3:
cd frontend
npm install
cp .env.example .env

# Start Vite development server
npm run dev
```
*Runs on `http://localhost:5173` (or the port Vite outputs in terminal).*

#### Step 6: Run Network Sensor
```bash
# Terminal 4 (Ensure Python venv is activated):
# Replay sample PCAP test file:
python -m sensor.src.main --mode pcap --file sensor/samples/sample_test.pcap --dataset nsl_kdd
```

#### Step 7: Access the SOC Dashboard
1. Open your browser and navigate to `http://localhost:8080` (Docker) or `http://localhost:5173` (Local Dev).
2. Log in with the default seeded administrator credentials:
   - **Email**: `admin@netshield.local`
   - **Password**: `AdminSecurePassword123!`

---

## 10. Network Sensor Configuration

The NetShield Network Sensor is located in `sensor/`. It extracts flow statistics from raw packets and sends structured prediction requests to the Node.js backend.

### Operational Modes

1. **PCAP Mode (`--mode pcap`)**: Reads a `.pcap` capture file sequentially, reassembles TCP/UDP flows using bidirectional flow keys (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`), flushes completed flows upon inactivity timeout, and submits them for inference.
2. **Live Capture Mode (`--mode live`)**: Uses Scapy's `AsyncSniffer` to listen on a designated network interface in real time.

> [!NOTE]
> Live capture requires administrator or root privileges:
> - **Windows**: Requires **Npcap** installed in "WinPcap API-compatible Mode". Run your terminal as Administrator.
> - **Linux / macOS**: Requires raw socket permissions (`sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)` or running with `sudo`).

### Sensor CLI Usage

```bash
# Display help
python -m sensor.src.main --help

# 1. Run PCAP mode on sample capture with NSL-KDD schema
python -m sensor.src.main --mode pcap --file sensor/samples/sample_test.pcap --dataset nsl_kdd

# 2. Run PCAP mode with CICIDS2017 schema
python -m sensor.src.main --mode pcap --file path/to/traffic.pcap --dataset cicids2017

# 3. Run Live capture on a specific network interface
python -m sensor.src.main --mode live --interface "Ethernet" --dataset nsl_kdd
```

### Sensor Settings Reference (`sensor/.env` or Environment Variables)

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `SENSOR_MODE` | `pcap` | Mode of operation: `pcap` or `live` |
| `PCAP_FILE` | `sensor/samples/sample_test.pcap` | Path to input PCAP file |
| `SENSOR_INTERFACE` | *(empty string)* | Network interface name for live sniffing |
| `DATASET_TYPE` | `nsl_kdd` | Target feature schema: `nsl_kdd` or `cicids2017` |
| `FLOW_TIMEOUT_SECONDS`| `30` | Inactivity interval before a flow is marked complete |
| `BACKEND_URL` | `http://localhost:5000` | Target URL for Node.js Express Backend |
| `ML_SERVICE_URL` | `http://localhost:8000` | Direct FastAPI URL (used as fallback) |
| `SENSOR_SERVICE_TOKEN`| *(configured in backend)* | Service-to-service auth header (`X-Service-Token`) |
| `REQUEST_TIMEOUT_MS` | `5000` | HTTP request timeout |
| `MAX_ACTIVE_FLOWS` | `10000` | Flow table capacity to protect memory |

---

## 11. API Documentation

### Default Service Base URLs
- **Node.js Backend**: `http://localhost:5000/api`
- **FastAPI ML Service**: `http://localhost:8000`

---

### FastAPI ML Microservice Endpoints

#### 1. Liveness & Readiness Probes
- `GET /live`: Confirms FastAPI event loop is running.
- `GET /ready`: Returns 200 OK if both `nsl_kdd` and `cicids2017` production models are loaded in memory.
- `GET /health`: Comprehensive health status.
  ```json
  // Response (200 OK)
  {
    "status": "healthy",
    "timestamp": "2026-11-28T12:00:00.000Z",
    "loaded_datasets": ["nsl_kdd", "cicids2017"]
  }
  ```

#### 2. Model Metadata Information
- `GET /model-info`: Returns active production model versions, algorithms, training sample sizes, and empirical accuracies.

#### 3. Direct ML Prediction
- `POST /predict`: Direct ML inference endpoint.
  - **Request Body**:
    ```json
    {
      "dataset_type": "nsl_kdd",
      "input_data": {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 215,
        "dst_bytes": 45076,
        "count": 1,
        "srv_count": 1
      }
    }
    ```
  - **Response (200 OK)**:
    ```json
    {
      "dataset_type": "nsl_kdd",
      "model_version": "NetShield-NSLKDD-XGBoost-v1.3",
      "records_processed": 1,
      "predictions": [
        {
          "prediction": "Normal",
          "prediction_index": 1,
          "confidence": 0.9984,
          "class_probabilities": {
            "DoS": 0.0002,
            "Normal": 0.9984,
            "Probe": 0.0011,
            "R2L": 0.0002,
            "U2R": 0.0001
          }
        }
      ]
    }
    ```

---

### Node.js Backend Endpoints

#### Authentication & Session (`/api/auth`)

| Endpoint | Method | Role | Description |
| :--- | :--- | :--- | :--- |
| `/api/auth/csrf` | `GET` | Public | Returns CSRF token and sets `XSRF-TOKEN` cookie |
| `/api/auth/register` | `POST` | Public / Admin | Registers a new user account |
| `/api/auth/login` | `POST` | Public | Authenticates credentials; sets HTTP-only `netshield_token` JWT cookie |
| `/api/auth/logout` | `POST` | Authenticated | Clears auth cookies |
| `/api/auth/me` | `GET` | Authenticated | Returns current authenticated user profile |

**Example Login Request:**
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@netshield.local", "password": "AdminSecurePassword123!"}'
```

---

#### Predictions & Ingestion (`/api/predictions`)

- `POST /api/predictions`: Ingests network flow features, queries the FastAPI service, persists the log document, triggers incident correlation, and emits real-time WebSocket events.
  - **Auth**: `ADMIN`, `ANALYST`, or `SERVICE` (via `X-Service-Token: <token>`).
  - **Request Body**:
    ```json
    {
      "datasetType": "nsl_kdd",
      "inputData": {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "private",
        "flag": "S0",
        "src_bytes": 0,
        "dst_bytes": 0,
        "count": 250,
        "srv_count": 10
      },
      "sourceInfo": {
        "src_ip": "192.168.1.105",
        "dst_ip": "10.0.0.1",
        "src_port": 49201,
        "dst_port": 80,
        "protocol": "TCP"
      }
    }
    ```
- `GET /api/predictions`: Paginated retrieval of historical prediction logs.

---

#### Threat Alerts (`/api/alerts`)

- `GET /api/alerts`: List alerts with pagination, severity filters (`low`, `medium`, `high`, `critical`), and status filters (`open`, `investigating`, `resolved`, `dismissed`).
- `GET /api/alerts/:id`: Retrieve alert details.
- `PATCH /api/alerts/:id`: Update alert status and resolution notes (Requires `ADMIN` or `ANALYST`).

---

#### Investigations & Incidents

- `GET /api/investigations/alerts/:id`: Returns unified correlation view for an alert, including related predictions and network origin history.
- `GET /api/operations/incidents`: Retrieve correlated operational incidents.
- `PATCH /api/operations/incidents/:id`: Update operational incident status.

---

#### Analytics & Metrics

- `GET /api/analytics/overview`: Overall system statistics (total predictions, total alerts, critical count).
- `GET /api/analytics/trends`: Time-series incident and prediction frequency.
- `GET /api/analytics/attacks`: Attack distribution breakdown by category.
- `GET /api/analytics/severity`: Severity breakdown counts.
- `GET /api/metrics`: Internal system latency, CPU, and throughput telemetry.

---

#### System Settings (`/api/settings`)

- `GET /api/settings`: Read system settings (retention days, alert thresholds, SMTP configuration).
- `PATCH /api/settings/:key`: Update setting value (`ADMIN` only).
- `POST /api/settings/test-email`: Test configured SMTP credentials.

---

## 12. Developer Contribution & Workflow Guide

### Development Principles
1. **Never Contaminate Data Splits**: All feature scaling, encoding, and selection transformers must be fitted strictly on training data. Never call `.fit()` or `.fit_transform()` on validation or test sets.
2. **Float32 Precision**: Keep large numerical arrays downcasted to `np.float32` to avoid out-of-memory errors on 8GB development systems.
3. **Defense in Depth**: Every state-changing API endpoint (`POST`, `PATCH`, `DELETE`) in the backend must require authentication, CSRF validation, and payload validation with Zod.

### Where to Add New Code

| Task | Target Directory | Instructions |
| :--- | :--- | :--- |
| **New API Routes** | `backend/src/routes/` & `backend/src/controllers/` | Register route in `apiRoutes.js`, add controller, validate inputs with Zod. |
| **Frontend Page / View** | `frontend/src/pages/` | Add page component, register route in `frontend/src/App.jsx`, add nav link in `Sidebar.jsx`. |
| **Preprocessing Logic** | `ml_service/src/preprocessing/` | Update preprocessor class, preserve `.fit_transform_train` vs `.transform_test` separation. |
| **New ML Model Experiment** | `ml_service/training/` | Write experimental script, save artifacts in an experimental subfolder under `artifacts/models/`. |
| **Sensor Feature Extraction**| `sensor/src/features/` | Update `nslKddFeatures.py` or `cicids2017Features.py` and update validator in `featureValidator.py`. |

### Running the Test Suites

Execute test suites across all components before submitting changes:

```bash
# 1. Run Backend Test Suite (Jest)
cd backend
npm test

# 2. Run Frontend Test Suite (Vitest)
cd ../frontend
npm test

# 3. Run ML Service Test Suite (Pytest)
cd ../ml_service
pytest tests/ -v

# 4. Run Sensor Test Suite (Pytest)
cd ../sensor
pytest tests/ -v

# 5. Run Full End-to-End Smoke Test (Requires services running)
cd ..
python scripts/verify_deployment.py
```

---

## 13. Troubleshooting Guide

### 1. Python Dependency or Module Import Errors
- **Symptom**: `ModuleNotFoundError: No module named 'ml_service'` or `'sensor'`
- **Cause**: Project root is not in your `PYTHONPATH`.
- **Fix**: Run scripts from the project root or use `python -m <module>`. If running standalone, set `PYTHONPATH`:
  ```powershell
  # Windows PowerShell
  $env:PYTHONPATH = (Get-Location).Path
  ```
  ```bash
  # Linux / macOS
  export PYTHONPATH=$(pwd)
  ```

### 2. Node.js / npm Dependency Errors
- **Symptom**: `npm ERR! code ERESOLVE` or `node_modules` missing
- **Cause**: Incompatible lockfile or corrupted cache.
- **Fix**:
  ```bash
  cd backend && rm -rf node_modules package-lock.json && npm install
  cd ../frontend && rm -rf node_modules package-lock.json && npm install
  ```

### 3. Missing Dataset Files
- **Symptom**: `FileNotFoundError: KDDTrain+.txt not found in data/raw/`
- **Cause**: Raw benchmark files were not placed in `data/raw/`.
- **Fix**: Download the datasets as instructed in [Section 4](#4-dataset-installation-and-configuration) and verify using the provided verification script.

### 4. Model Artifact Not Found
- **Symptom**: `FastAPI 503 Service Unavailable: Not all production models are loaded.`
- **Cause**: The serialized `.joblib` files in `artifacts/v1.3/nsl_kdd/` or `artifacts/v1.2/cicids2017/` are missing or corrupted.
- **Fix**: Inspect the directories. If files are missing, run the packaging scripts:
  ```bash
  python ml_service/src/production/bundle_production_artifacts.py
  ```

### 5. MongoDB Connection Failure
- **Symptom**: `MongoServerSelectionError: connect ECONNREFUSED 127.0.0.1:27017`
- **Cause**: Local MongoDB service is not running or Docker container failed to initialize.
- **Fix**:
  - Local: Ensure MongoDB service is started (`net start MongoDB` on Windows or `sudo systemctl start mongod` on Linux).
  - Docker: Run `docker compose logs mongodb` to inspect initialization errors. Check authentication parameters in `.env`.

### 6. CORS Errors in Frontend Console
- **Symptom**: `Access to XMLHttpRequest at '...' from origin 'http://localhost:8080' has been blocked by CORS policy`
- **Cause**: The origin of the frontend is missing from `CORS_ORIGINS` in `backend/.env`.
- **Fix**: Add the frontend URL to `CORS_ORIGINS` (comma-separated):
  ```ini
  CORS_ORIGINS=http://localhost:8080,http://127.0.0.1:8080,http://localhost:5173
  ```
  Restart the backend service.

### 7. Port Conflicts (e.g., Port 5000 or 8080 in use)
- **Symptom**: `bind: address already in use`
- **Diagnose**:
  - Windows: `netstat -ano | findstr :5000`
  - Linux/macOS: `lsof -i :5000`
- **Fix**: Stop conflicting processes or change the external port mapping in `docker-compose.yml` (e.g., change `"8080:5173"` to `"8090:5173"`).

### 8. Sensor Authentication Failures
- **Symptom**: `[Prediction Delivery Failed]: 401 Unauthorized`
- **Cause**: Mismatch between `SENSOR_SERVICE_TOKEN` in `sensor/.env` and `backend/.env`.
- **Fix**: Verify that both files share the exact same `SENSOR_SERVICE_TOKEN` value.

### 9. PCAP Processing Generates Zero Packets
- **Symptom**: `Packets Captured: 0` in Sensor Summary
- **Cause**: File path is incorrect or the PCAP file is corrupted.
- **Fix**: Ensure the path provided to `--file` exists. Test with the bundled sample:
  ```bash
  python -m sensor.src.main --mode pcap --file sensor/samples/sample_test.pcap --dataset nsl_kdd
  ```

---

## 14. Security & Compliance Considerations

- **Dual-Token Authentication**: Web users authenticate via an HTTP-only, `SameSite=Lax` cookie storing a signed JWT. Automated agents (e.g., Network Sensor) authenticate via the internal `X-Service-Token` header.
- **CSRF Protection**: State-changing endpoints are protected with double-submit CSRF tokens. The frontend automatically reads the `XSRF-TOKEN` cookie and attaches the `X-XSRF-TOKEN` header on all mutation requests.
- **Role-Based Access Control (RBAC)**:
  - `ADMIN`: Full access to settings, user management, and email notifications.
  - `ANALYST`: Manage alerts, view analytics, inspect predictions, update incident statuses.
  - `VIEWER`: Read-only access to dashboard charts and feeds.
  - `SERVICE`: Dedicated service role for internal telemetry and sensor ingestion.
- **Authentication Rate Limiting**: Enforces strict throttling on `/api/auth/login` and `/api/auth/register` (max 10 attempts per 15-minute window) using an in-memory sliding window rate limiter.
- **Data Protection & Sanitization**: FastAPI and Express sanitize all internal server error messages before returning HTTP responses, preventing stack trace or internal filesystem path leakage.

---

## License & Citation

NetShield is developed as an academic and research project for network security analysis.
Distributed under the MIT License. See `LICENSE` for details.
