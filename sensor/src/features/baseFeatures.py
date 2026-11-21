import math
import numpy as np
from typing import Dict, Any, List
from sensor.src.models.flow import Flow

def calculate_stats(values: List[float]) -> Dict[str, float]:
    """
    Computes min, max, mean, and standard deviation for a list of numerical values.
    """
    if not values:
        return {"min": 0.0, "max": 0.0, "mean": 0.0, "std": 0.0}

    arr = np.array(values, dtype=np.float64)
    return {
        "min": float(np.min(arr)),
        "max": float(np.max(arr)),
        "mean": float(np.mean(arr)),
        "std": float(np.std(arr)) if len(arr) > 1 else 0.0
    }

def calculate_iats(timestamps: List[float]) -> List[float]:
    """
    Calculates inter-arrival times between consecutive packet timestamps in microseconds or seconds.
    """
    if len(timestamps) < 2:
        return []
    sorted_ts = sorted(timestamps)
    return [sorted_ts[i] - sorted_ts[i-1] for i in range(1, len(sorted_ts))]

def calculate_active_idle_times(timestamps: List[float], threshold_sec: float = 5.0) -> Dict[str, List[float]]:
    """
    Computes active and idle durations in microseconds per CICFlowMeter specification.
    An idle period is an inter-arrival time between consecutive packets >= threshold_sec (5.0s).
    Active periods are the durations of continuous activity between idle periods.
    """
    if len(timestamps) < 2:
        return {"active": [0.0], "idle": [0.0]}

    sorted_ts = sorted(timestamps)
    active_times = []
    idle_times = []

    current_active_start = sorted_ts[0]
    prev_ts = sorted_ts[0]

    for ts in sorted_ts[1:]:
        gap = ts - prev_ts
        if gap >= threshold_sec:
            idle_times.append(gap * 1e6)
            active_dur = (prev_ts - current_active_start) * 1e6
            if active_dur > 0:
                active_times.append(active_dur)
            current_active_start = ts
        prev_ts = ts

    last_active = (prev_ts - current_active_start) * 1e6
    if last_active > 0 or not active_times:
        active_times.append(max(0.0, last_active))
    if not idle_times:
        idle_times.append(0.0)

    return {"active": active_times, "idle": idle_times}


class BaseFeatureExtractor:
    """
    Extracts raw deterministic flow statistics from a stateful Flow object.
    """
    @staticmethod
    def extract(flow: Flow) -> Dict[str, Any]:
        duration = flow.duration

        # Packet length statistics
        pkt_len_stats = calculate_stats(flow.pkt_lengths)
        fwd_pkt_len_stats = calculate_stats(flow.fwd_pkt_lengths)
        bwd_pkt_len_stats = calculate_stats(flow.bwd_pkt_lengths)

        # IAT statistics (in microseconds for CICIDS2017 compatibility)
        all_iats_us = [iat * 1e6 for iat in calculate_iats(flow.all_timestamps)]
        fwd_iats_us = [iat * 1e6 for iat in calculate_iats(flow.fwd_timestamps)]
        bwd_iats_us = [iat * 1e6 for iat in calculate_iats(flow.bwd_timestamps)]

        flow_iat_stats = calculate_stats(all_iats_us)
        fwd_iat_stats = calculate_stats(fwd_iats_us)
        bwd_iat_stats = calculate_stats(bwd_iats_us)

        # Active and Idle temporal statistics (in microseconds)
        ai_times = calculate_active_idle_times(flow.all_timestamps, threshold_sec=5.0)
        active_stats = calculate_stats(ai_times["active"])
        idle_stats = calculate_stats(ai_times["idle"])

        # Rates (packets/sec, bytes/sec)
        dur_sec = duration if duration > 0 else 1e-6
        flow_bytes_per_sec = flow.total_bytes / dur_sec
        flow_packets_per_sec = flow.total_packets / dur_sec
        fwd_packets_per_sec = flow.fwd_packets / dur_sec
        bwd_packets_per_sec = flow.bwd_packets / dur_sec

        # Down/Up ratio
        down_up_ratio = flow.bwd_packets / flow.fwd_packets if flow.fwd_packets > 0 else 0.0

        return {
            "duration": duration,
            "duration_us": duration * 1e6,
            "total_packets": flow.total_packets,
            "fwd_packets": flow.fwd_packets,
            "bwd_packets": flow.bwd_packets,
            "total_bytes": flow.total_bytes,
            "fwd_bytes": flow.fwd_bytes,
            "bwd_bytes": flow.bwd_bytes,
            "flow_bytes_per_sec": flow_bytes_per_sec,
            "flow_packets_per_sec": flow_packets_per_sec,
            "fwd_packets_per_sec": fwd_packets_per_sec,
            "bwd_packets_per_sec": bwd_packets_per_sec,
            "pkt_len_stats": pkt_len_stats,
            "fwd_pkt_len_stats": fwd_pkt_len_stats,
            "bwd_pkt_len_stats": bwd_pkt_len_stats,
            "flow_iat_stats": flow_iat_stats,
            "fwd_iat_stats": fwd_iat_stats,
            "bwd_iat_stats": bwd_iat_stats,
            "fwd_iat_total_us": sum(fwd_iats_us) if fwd_iats_us else 0.0,
            "bwd_iat_total_us": sum(bwd_iats_us) if bwd_iats_us else 0.0,
            "active_stats": active_stats,
            "idle_stats": idle_stats,
            "fin_count": flow.fin_count,
            "syn_count": flow.syn_count,
            "rst_count": flow.rst_count,
            "psh_count": flow.psh_count,
            "ack_count": flow.ack_count,
            "urg_count": flow.urg_count,
            "ece_count": flow.ece_count,
            "cwr_count": flow.cwr_count,
            "fwd_psh_flags": flow.fwd_psh_flags,
            "fwd_urg_flags": flow.fwd_urg_flags,
            "bwd_psh_flags": flow.bwd_psh_flags,
            "bwd_urg_flags": flow.bwd_urg_flags,
            "init_win_bytes_fwd": flow.init_win_bytes_fwd,
            "init_win_bytes_bwd": flow.init_win_bytes_bwd,
            "down_up_ratio": down_up_ratio,
            "src_port": flow.key.src_port,
            "dst_port": flow.key.dst_port,
            "protocol": flow.key.protocol
        }
