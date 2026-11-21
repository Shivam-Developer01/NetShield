from typing import Dict, Any, Optional
from sensor.src.models.flow import Flow
from sensor.src.features.baseFeatures import BaseFeatureExtractor

# Common Port to NSL-KDD Service Mapping
PORT_SERVICE_MAP = {
    80: "http",
    443: "http",
    8080: "http",
    21: "ftp",
    20: "ftp_data",
    25: "smtp",
    53: "domain_u",
    22: "ssh",
    23: "telnet",
    110: "pop_3",
    143: "imap4",
    123: "ntp",
    67: "dhcp",
    68: "dhcp",
    79: "finger",
    111: "sunrpc",
    514: "syslog",
    161: "snmp"
}

def map_service(port: int, protocol: str) -> str:
    if protocol == "icmp":
        return "eco_i"
    return PORT_SERVICE_MAP.get(port, "private" if port > 1024 else "other")

def map_flag(flow: Flow) -> str:
    """
    Derives canonical NSL-KDD connection flag from TCP flag counts.
    """
    if flow.key.protocol != "tcp":
        return "SF"

    if flow.syn_count > 0 and flow.ack_count == 0 and flow.rst_count == 0:
        return "S0"
    elif flow.rst_count > 0:
        return "REJ"
    elif flow.syn_count > 0 and flow.ack_count > 0:
        return "SF"
    elif flow.fin_count > 0:
        return "SF"
    return "SF"


class NSLKDDFeatureMapper:
    """
    Transforms raw flow statistics into exact 41-feature dictionary expected by NSL-KDD preprocessor.
    Supports dynamic sliding-window traffic statistics when window_stats dictionary is provided.
    """
    @staticmethod
    def map_flow(flow: Flow, active_flows_count: int = 1, window_stats: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        base = BaseFeatureExtractor.extract(flow)

        protocol = flow.key.protocol.lower()
        if protocol not in ["tcp", "udp", "icmp"]:
            protocol = "tcp"

        service = map_service(flow.key.dst_port, protocol)
        flag = map_flag(flow)
        land = 1 if (flow.key.src_ip == flow.key.dst_ip and flow.key.src_port == flow.key.dst_port) else 0

        serror = 1.0 if (flow.syn_count > 0 and flow.ack_count == 0) else 0.0
        rerror = 1.0 if flow.rst_count > 0 else 0.0

        ws = window_stats or {}
        count_val = ws.get("count", max(1, active_flows_count))
        srv_count_val = ws.get("srv_count", max(1, active_flows_count))
        same_srv_rate = ws.get("same_srv_rate", 1.0)
        diff_srv_rate = ws.get("diff_srv_rate", 0.0)
        srv_diff_host_rate = ws.get("srv_diff_host_rate", 0.0)
        dst_host_count = ws.get("dst_host_count", min(255, max(1, active_flows_count)))
        dst_host_srv_count = ws.get("dst_host_srv_count", min(255, max(1, active_flows_count)))
        dst_host_same_srv_rate = ws.get("dst_host_same_srv_rate", 1.0)
        dst_host_diff_srv_rate = ws.get("dst_host_diff_srv_rate", 0.0)
        dst_host_same_src_port_rate = ws.get("dst_host_same_src_port_rate", 1.0)
        dst_host_srv_diff_host_rate = ws.get("dst_host_srv_diff_host_rate", 0.0)

        return {
            "duration": int(round(flow.duration)),
            "protocol_type": protocol,
            "service": service,
            "flag": flag,
            "src_bytes": flow.fwd_bytes,
            "dst_bytes": flow.bwd_bytes,
            "land": land,
            "wrong_fragment": 0,
            "urgent": flow.urg_count,
            # Unobservable host-based features strictly defaulted to safe baseline 0
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 1 if (service in ["http", "smtp", "ftp"] and flow.total_packets > 3) else 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            # Dynamic time-window traffic statistics
            "count": count_val,
            "srv_count": srv_count_val,
            "serror_rate": serror,
            "srv_serror_rate": serror,
            "rerror_rate": rerror,
            "srv_rerror_rate": rerror,
            "same_srv_rate": same_srv_rate,
            "diff_srv_rate": diff_srv_rate,
            "srv_diff_host_rate": srv_diff_host_rate,
            "dst_host_count": dst_host_count,
            "dst_host_srv_count": dst_host_srv_count,
            "dst_host_same_srv_rate": dst_host_same_srv_rate,
            "dst_host_diff_srv_rate": dst_host_diff_srv_rate,
            "dst_host_same_src_port_rate": dst_host_same_src_port_rate,
            "dst_host_srv_diff_host_rate": dst_host_srv_diff_host_rate,
            "dst_host_serror_rate": serror,
            "dst_host_srv_serror_rate": serror,
            "dst_host_rerror_rate": rerror,
            "dst_host_srv_rerror_rate": rerror
        }
