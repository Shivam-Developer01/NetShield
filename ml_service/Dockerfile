# NetShield ML Inference Service Dockerfile
# Production-ready deployment container with serialized production model bundles

FROM python:3.12-slim

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

WORKDIR /app

# Install system dependencies (build-essential needed for lightgbm/xgboost if needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency definition and install Python requirements
COPY ml_service/requirements.txt /app/ml_service/requirements.txt
RUN pip install --no-cache-dir -r /app/ml_service/requirements.txt

# Copy ML microservice source code
COPY ml_service/src /app/ml_service/src
COPY ml_service/run_server.py /app/ml_service/run_server.py

# Copy serialized production model bundles and verified models
COPY artifacts/production /app/artifacts/production
COPY artifacts /app/artifacts

# Environment variables for service execution
ENV HOST=0.0.0.0
ENV PORT=8000
ENV WORKERS=1
ENV LOG_LEVEL=info
ENV CORS_ORIGINS=http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

# Launch FastAPI microservice
CMD ["python", "ml_service/run_server.py"]
