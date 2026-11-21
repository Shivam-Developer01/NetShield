import math
from typing import Dict, Any, Tuple, Optional

class FeatureValidator:
    """
    Validates extracted feature payloads before transmitting to FastAPI / Node.js backend.
    Enforces non-negative counters, finite numeric check, and field schema completeness.
    """

    NSL_KDD_REQUIRED_KEYS = [
        "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
        "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
        "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
        "num_shells", "num_access_files", "is_host_login", "is_guest_login", "count",
        "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
        "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
        "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
        "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
        "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
    ]

    CICIDS2017_REQUIRED_KEYS = [
        "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
        "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
        "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
        "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
        "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean",
        "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
        "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Fwd URG Flags",
        "Bwd PSH Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length",
        "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
        "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
        "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
        "URG Flag Count", "CWE Flag Count", "ECE Flag Count", "CWR Flag Count", "Down/Up Ratio",
        "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
        "Fwd Header Length.1", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk",
        "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",
        "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes",
        "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward",
        "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
        "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean",
        "Idle Std", "Idle Max", "Idle Min"
    ]

    @classmethod
    def validate(cls, payload: Dict[str, Any], dataset_type: str) -> Tuple[bool, Optional[str]]:
        if not isinstance(payload, dict):
            return False, "Feature payload must be a dictionary."

        if not payload:
            return False, "Feature payload cannot be empty."

        target_dataset = dataset_type.lower().replace("-", "_")
        required_keys = cls.NSL_KDD_REQUIRED_KEYS if target_dataset == "nsl_kdd" else cls.CICIDS2017_REQUIRED_KEYS

        # 1. Key presence check
        missing_keys = [k for k in required_keys if k not in payload]
        if missing_keys:
            return False, f"Missing required feature keys ({len(missing_keys)} missing): {missing_keys[:3]}"

        # 2. Value type & NaN/Inf check
        for key, val in payload.items():
            if isinstance(val, (int, float)):
                if math.isnan(val) or math.isinf(val):
                    return False, f"Invalid numeric value '{val}' (NaN or Infinity) in feature '{key}'."

        # 3. Non-negative check on counters
        for key in ["duration", "src_bytes", "dst_bytes", "count", "srv_count", "Flow Duration", "Total Fwd Packets", "Total Backward Packets"]:
            if key in payload and isinstance(payload[key], (int, float)):
                if payload[key] < 0:
                    return False, f"Non-negative counter violation in feature '{key}': {payload[key]}"

        return True, None
