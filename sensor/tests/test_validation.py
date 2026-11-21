import math
from sensor.src.features.featureValidator import FeatureValidator

def test_validator_valid_nsl_kdd():
    payload = {
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
    is_valid, err = FeatureValidator.validate(payload, "nsl_kdd")
    assert is_valid is True
    assert err is None

def test_validator_missing_key():
    payload = {"duration": 0, "protocol_type": "tcp"}
    is_valid, err = FeatureValidator.validate(payload, "nsl_kdd")
    assert is_valid is False
    assert "Missing required feature keys" in err

def test_validator_nan_rejection():
    payload = {
        "Destination Port": 80, "Flow Duration": math.nan, "Total Fwd Packets": 1
    }
    is_valid, err = FeatureValidator.validate(payload, "cicids2017")
    assert is_valid is False
    assert "NaN or Infinity" in err or "Missing required feature keys" in err

def test_validator_negative_counter_rejection():
    payload = {
        "duration": -5, "protocol_type": "tcp", "service": "http", "flag": "SF",
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
    is_valid, err = FeatureValidator.validate(payload, "nsl_kdd")
    assert is_valid is False
    assert "Non-negative counter violation" in err
