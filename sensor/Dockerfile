# NetShield Network Sensor Production Microservice Container
FROM python:3.12-slim

WORKDIR /app

# Install system utilities (libpcap-dev for Scapy live capture capabilities on Linux)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    gcc \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

COPY sensor/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY sensor/src/ ./sensor/src/
COPY sensor/samples/ ./sensor/samples/

ENV PYTHONUNBUFFERED=1
ENV SENSOR_MODE=pcap
ENV PCAP_FILE=sensor/samples/sample_test.pcap
ENV DATASET_TYPE=nsl_kdd
ENV BACKEND_URL=http://backend:5000
ENV ML_SERVICE_URL=http://ml-service:8000

CMD ["python", "-m", "sensor.src.main"]
