import pytest
from unittest.mock import patch, MagicMock
from sensor.src.inference.mlClient import SensorMLClient

def test_ml_client_initialization():
    client = SensorMLClient(
        backend_url="http://localhost:5000",
        ml_service_url="http://localhost:8000",
        timeout_ms=3000,
        service_token="test_service_token_123"
    )
    assert client.backend_url == "http://localhost:5000"
    assert client.ml_service_url == "http://localhost:8000"
    assert client.timeout_sec == 3.0
    assert client.service_token == "test_service_token_123"

def test_ml_client_auth_connection_failure():
    client = SensorMLClient(backend_url="http://localhost:59999")
    auth_success = client.authenticate_sensor()
    assert auth_success is False

def test_ml_client_send_prediction_fallback():
    client = SensorMLClient(
        backend_url="http://localhost:59999",
        ml_service_url="http://localhost:8000"
    )
    # Direct FastAPI predict test
    sample_payload = {
        "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF",
        "src_bytes": 100, "dst_bytes": 200, "land": 0, "wrong_fragment": 0, "urgent": 0,
        "hot": 0, "num_failed_logins": 0, "logged_in": 1, "num_compromised": 0, "root_shell": 0,
        "su_attempted": 0, "num_root": 0, "num_file_creations": 0, "num_shells": 0, "num_access_files": 0,
        "is_host_login": 0, "is_guest_login": 0, "count": 1, "srv_count": 1, "serror_rate": 0.0,
        "srv_serror_rate": 0.0, "rerror_rate": 0.0, "srv_rerror_rate": 0.0, "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0, "dst_host_count": 1, "dst_host_srv_count": 1,
        "dst_host_same_srv_rate": 1.0, "dst_host_diff_srv_rate": 0.0, "dst_host_same_src_port_rate": 1.0,
        "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
        "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0
    }
    success, res = client.send_prediction("nsl_kdd", sample_payload)
    assert success is True
    assert "predictions" in res

def test_ml_client_service_token_header_in_requests():
    client = SensorMLClient(
        backend_url="http://backend.test:5000",
        service_token="secure_token_abc"
    )
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"success": True, "predictions": [{"prediction": "Normal"}]}

    with patch.object(client.session, "post", return_value=mock_resp) as mock_post:
        success, res = client.send_prediction("nsl_kdd", {"duration": 0})
        assert success is True
        mock_post.assert_called_once()
        headers = mock_post.call_args[1]["headers"]
        assert headers.get("X-Service-Token") == "secure_token_abc"

def test_ml_client_send_telemetry_with_service_token():
    client = SensorMLClient(
        backend_url="http://backend.test:5000",
        service_token="secure_token_abc"
    )
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch.object(client.session, "post", return_value=mock_resp) as mock_post:
        success = client.send_telemetry({"packetsProcessed": 10, "status": "healthy"})
        assert success is True
        mock_post.assert_called_once()
        headers = mock_post.call_args[1]["headers"]
        assert headers.get("X-Service-Token") == "secure_token_abc"
        assert mock_post.call_args[0][0] == "http://backend.test:5000/api/sensor/telemetry"

def test_ml_client_send_prediction_with_source_info():
    client = SensorMLClient(
        backend_url="http://backend.test:5000",
        service_token="secure_token_abc"
    )
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"success": True, "predictions": [{"prediction": "Normal"}]}

    source_info = {
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.100",
        "src_port": 52341,
        "dst_port": 80,
        "protocol": "TCP",
        "flow_id": "192.168.1.10:52341->192.168.1.100:80_TCP"
    }

    with patch.object(client.session, "post", return_value=mock_resp) as mock_post:
        success, res = client.send_prediction("nsl_kdd", {"duration": 0}, source_info=source_info)
        assert success is True
        mock_post.assert_called_once()
        sent_payload = mock_post.call_args[1]["json"]
        assert "sourceInfo" in sent_payload
        s_info = sent_payload["sourceInfo"]
        assert s_info["sensor"] == "NetShield-Scapy-Sensor"
        assert s_info["src_ip"] == "192.168.1.10"
        assert s_info["dst_ip"] == "192.168.1.100"
        assert s_info["src_port"] == 52341
        assert s_info["dst_port"] == 80
        assert s_info["protocol"] == "TCP"
        assert s_info["flow_id"] == "192.168.1.10:52341->192.168.1.100:80_TCP"

