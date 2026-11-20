# NetShield Machine Learning Microservice (`ml_service/`)

Production ML microservice powering the **NetShield AI-Powered Network Intrusion Detection System**.

---

## 1. Production Features & Observability
- **Containerized**: Deployed via `ml_service/Dockerfile` (`python:3.12-slim`).
- **Request Correlation**: Extracts `X-Request-ID` header from request (or generates a UUID), attaches `X-Request-ID` to response headers, and logs correlation ID in structured logs.
- **Error Sanitization**: Catch-all exception handlers suppress raw stack trace leakage and sanitize Pydantic validation errors (HTTP 422).
- **Lifespan Manager**: Loads serialized production model bundles (`nsl_kdd` & `cicids2017`) at server startup.

---

## 2. Directory Structure

```
ml_service/
├── .env.example               # Environment configuration template
├── Dockerfile                 # Production Python 3.12 container specification
├── README.md                  # Microservice documentation
├── run_server.py              # Standalone production service runner
├── src/
│   ├── api/
│   │   ├── app.py             # FastAPI application, correlation middleware, exception sanitization
│   │   ├── routes.py          # GET /health, GET /model-info, POST /predict endpoints
│   │   └── schemas.py         # Pydantic V2 request & response validation schemas
│   ├── features/
│   │   └── feature_selector.py# NetShield custom feature selection transformer
│   ├── inference/
│   │   └── pipeline.py        # Decoupled 5-step production inference pipeline
│   ├── models/
│   │   ├── train_baseline_models.py
│   │   └── train_ensemble_models.py
│   └── preprocessing/
│       ├── nsl_kdd_preprocess.py
│       └── cicids2017_preprocess.py
└── tests/
    ├── run_tests.py           # Master validation test runner (24/24 tests)
    ├── test_api.py            # FastAPI endpoints test suite
    ├── test_baseline_models.py
    ├── test_ensemble_models.py
    ├── test_feature_selection.py
    ├── test_preprocessing.py
    └── test_production_inference.py
```

---

## 3. Quickstart Guide

### 1. Launch FastAPI Server
```bash
python ml_service/run_server.py
```

### 2. Interactive Documentation
- **OpenAPI Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc UI**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

### 3. Run Validation Test Suite
```bash
python ml_service/tests/run_tests.py
```
- Passes 24/24 tests verifying raw data integrity, preprocessors, feature selectors, baseline models, ensemble models, production artifact bundles, inference pipelines, and FastAPI HTTP endpoints.
