import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class SensorSettings(BaseSettings):
    sensor_mode: str = Field(default="pcap", description="Sensor capture mode: 'pcap' or 'live'")
    sensor_interface: str = Field(default="", description="Network interface name for live mode")
    pcap_file: str = Field(default="sensor/samples/sample_test.pcap", description="PCAP file path for offline mode")
    dataset_type: str = Field(default="nsl_kdd", description="Default model pipeline target: 'nsl_kdd' or 'cicids2017'")
    flow_timeout_seconds: int = Field(default=30, description="Flow idle timeout in seconds")
    backend_url: str = Field(default="http://localhost:5000", description="Node.js Express backend base URL")
    ml_service_url: str = Field(default="http://localhost:8000", description="FastAPI ML service base URL")
    sensor_service_token: str = Field(default="netshield_sensor_internal_service_token_phase20_11_secure", description="Internal machine-to-machine service authentication token")
    request_timeout_ms: int = Field(default=5000, description="HTTP client request timeout in milliseconds")
    batch_size: int = Field(default=1, description="Number of flow records per prediction request batch")
    max_active_flows: int = Field(default=10000, description="Maximum concurrent active flows in table")
    max_packet_size: int = Field(default=65535, description="Maximum allowed packet payload size")
    max_queue_size: int = Field(default=50000, description="Maximum packet queue buffer size")
    log_level: str = Field(default="INFO", description="Logging verbosity: DEBUG, INFO, WARN, ERROR")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

def get_settings() -> SensorSettings:
    return SensorSettings()
