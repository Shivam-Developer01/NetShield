import os
import uuid
import time
import requests
from typing import Dict, Any, Tuple, Optional
from sensor.src.utils.logger import get_logger

logger = get_logger("sensor-ml-client")

class SensorMLClient:
    """
    HTTP client for delivering validated flow features to Node.js backend (or FastAPI direct).
    Enforces service-to-service authentication (X-Service-Token), request correlation IDs (X-Request-ID),
    timeout handling, and exponential backoff retry.
    """
    def __init__(
        self,
        backend_url: str = "http://localhost:5000",
        ml_service_url: str = "http://localhost:8000",
        timeout_ms: int = 5000,
        max_retries: int = 3,
        service_token: Optional[str] = None
    ):
        self.backend_url = backend_url.rstrip("/")
        self.ml_service_url = ml_service_url.rstrip("/")
        self.timeout_sec = timeout_ms / 1000.0
        self.max_retries = max_retries
        self.session = requests.Session()

        # Service-to-Service authentication token
        self.service_token: Optional[str] = service_token or os.environ.get("SENSOR_SERVICE_TOKEN")
        if not self.service_token:
            try:
                from sensor.src.config.settings import get_settings
                self.service_token = get_settings().sensor_service_token
            except Exception:
                self.service_token = None

        # Fallback session cookie/auth if authenticated with Node.js backend
        self.auth_cookie: Optional[str] = None
        self.csrf_token: Optional[str] = None
        self.jwt_token: Optional[str] = None

    def authenticate_sensor(self, email: str = "admin@netshield.local", password: str = "AdminSecurePassword123!") -> bool:
        """
        Authenticates with Node.js Express backend to obtain JWT cookie & CSRF token if required by backend RBAC.
        Used as fallback when service token is not configured.
        """
        url = f"{self.backend_url}/api/auth/login"
        self.session.cookies.clear()
        try:
            res = self.session.post(url, json={"email": email, "password": password}, timeout=self.timeout_sec)
            if res.status_code == 200:
                data = res.json()
                self.jwt_token = data.get("token")
                self.csrf_token = data.get("csrfToken")
                logger.info("Sensor successfully authenticated with Node.js Express Backend via login.")
                return True
            else:
                logger.warning(f"Backend authentication warning (HTTP {res.status_code}). Will attempt predictions.")
                return False
        except Exception as err:
            logger.warning(f"Could not connect to backend auth endpoint: {err}. Sensor will attempt direct/unauthenticated requests.")
            return False

    def send_prediction(self, dataset_type: str, input_data: Dict[str, Any], correlation_id: Optional[str] = None, source_info: Optional[Dict[str, Any]] = None) -> Tuple[bool, Dict[str, Any]]:
        """
        Transmits single feature record or batch to Node.js backend POST /api/predictions.
        Falls back to direct FastAPI POST /predict if backend is unreachable.
        """
        req_id = correlation_id or f"sensor-{uuid.uuid4().hex[:12]}"
        
        # Primary target: Node.js Backend POST /api/predictions
        backend_target = f"{self.backend_url}/api/predictions"
        merged_source_info = {"sensor": "NetShield-Scapy-Sensor", "correlationId": req_id}
        if source_info:
            merged_source_info.update(source_info)

        payload = {
            "datasetType": dataset_type,
            "inputData": input_data,
            "sourceInfo": merged_source_info
        }

        headers = {
            "Content-Type": "application/json",
            "X-Request-ID": req_id
        }
        if self.service_token:
            headers["X-Service-Token"] = self.service_token
        elif self.jwt_token:
            headers["Authorization"] = f"Bearer {self.jwt_token}"
            if self.csrf_token:
                headers["Cookie"] = f"netshield_token={self.jwt_token}; XSRF-TOKEN={self.csrf_token}"
                headers["X-CSRF-Token"] = self.csrf_token
                headers["X-XSRF-Token"] = self.csrf_token

        for attempt in range(1, self.max_retries + 1):
            try:
                res = self.session.post(backend_target, json=payload, headers=headers, timeout=self.timeout_sec)
                if res.status_code in (200, 201):
                    return True, res.json()
                elif res.status_code in (401, 403):
                    # Only attempt browser-style re-authenticating if not using service token
                    if not self.service_token and attempt == 1 and self.authenticate_sensor():
                        if self.csrf_token:
                            headers["X-CSRF-Token"] = self.csrf_token
                        continue
                    logger.error(f"[HTTP {res.status_code}] Backend rejected prediction request (X-Request-ID: {req_id}): {res.text}")
                    return False, {"error": "RBAC_OR_CSRF_REJECTION", "status": res.status_code}
                else:
                    logger.warning(f"[Attempt {attempt}/{self.max_retries}] Backend error {res.status_code}. Retrying...")
            except requests.exceptions.RequestException as err:
                logger.warning(f"[Attempt {attempt}/{self.max_retries}] Backend connection error: {err}")

            if attempt < self.max_retries:
                time.sleep(0.3 * (2 ** (attempt - 1)))

        # Fallback target: Direct FastAPI ML Service POST /predict
        logger.info(f"Node.js Backend unavailable. Attempting direct FastAPI fallback ({self.ml_service_url}/predict)...")
        ml_target = f"{self.ml_service_url}/predict"
        ml_payload = {
            "dataset_type": dataset_type,
            "input_data": input_data
        }

        try:
            res = self.session.post(ml_target, json=ml_payload, headers={"X-Request-ID": req_id}, timeout=self.timeout_sec)
            if res.status_code == 200:
                return True, res.json()
            else:
                return False, {"error": "FASTAPI_REJECTION", "status": res.status_code, "message": res.text}
        except Exception as err:
            logger.error(f"FastAPI direct connection failed: {err}")
            return False, {"error": "CONNECTION_FAILED", "message": str(err)}

    def send_telemetry(self, telemetry_data: Dict[str, Any]) -> bool:
        """
        Sends aggregate sensor operational telemetry counters to Node.js backend POST /api/sensor/telemetry.
        """
        url = f"{self.backend_url}/api/sensor/telemetry"
        headers = {
            "Content-Type": "application/json"
        }
        if self.service_token:
            headers["X-Service-Token"] = self.service_token
        try:
            res = self.session.post(url, json=telemetry_data, headers=headers, timeout=self.timeout_sec)
            return res.status_code == 200
        except Exception as err:
            logger.debug(f"Telemetry submission error: {err}")
            return False
