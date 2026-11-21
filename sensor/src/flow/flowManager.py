from collections import deque
import time
from typing import Dict, List, Optional, Any
from sensor.src.models.flow import FlowKey, Flow, PacketMetadata
from sensor.src.flow.flowTimeout import FlowTimeoutTracker
from sensor.src.utils.logger import get_logger

logger = get_logger("sensor-flow-manager")

class FlowManager:
    """
    Manages active 5-tuple flow aggregation table, packet routing, and flow timeouts.
    Maintains a rolling connection history window for dynamic inter-flow feature calculations.
    """
    def __init__(self, timeout_seconds: int = 30, max_active_flows: int = 10000, history_window_size: int = 100):
        self.timeout_seconds = timeout_seconds
        self.max_active_flows = max_active_flows
        self.active_flows: Dict[FlowKey, Flow] = {}
        self.timeout_tracker = FlowTimeoutTracker(timeout_seconds)
        self.flow_history: deque = deque(maxlen=history_window_size)

        # Telemetry counters
        self.total_packets_processed: int = 0
        self.total_flows_generated: int = 0

    def _record_flow_history(self, flow: Flow):
        self.flow_history.append({
            "timestamp": flow.last_time,
            "src_ip": flow.key.src_ip,
            "dst_ip": flow.key.dst_ip,
            "src_port": flow.key.src_port,
            "dst_port": flow.key.dst_port,
            "protocol": flow.key.protocol,
            "duration": flow.duration
        })

    def get_window_stats(self, flow: Flow) -> Dict[str, Any]:
        """
        Computes rolling window connection rates for NSL-KDD features based on recent flow history.
        """
        if not self.flow_history:
            return {
                "count": 1,
                "srv_count": 1,
                "same_srv_rate": 1.0,
                "diff_srv_rate": 0.0,
                "srv_diff_host_rate": 0.0,
                "dst_host_count": 1,
                "dst_host_srv_count": 1,
                "dst_host_same_srv_rate": 1.0,
                "dst_host_diff_srv_rate": 0.0,
                "dst_host_same_src_port_rate": 1.0,
                "dst_host_srv_diff_host_rate": 0.0
            }

        dst_ip = flow.key.dst_ip
        dst_port = flow.key.dst_port
        src_port = flow.key.src_port

        same_dst = [f for f in self.flow_history if f["dst_ip"] == dst_ip]
        same_srv = [f for f in self.flow_history if f["dst_port"] == dst_port]
        same_dst_same_srv = [f for f in same_dst if f["dst_port"] == dst_port]
        same_dst_same_src_port = [f for f in same_dst if f["src_port"] == src_port]
        same_srv_diff_dst = [f for f in same_srv if f["dst_ip"] != dst_ip]

        dst_cnt = max(1, len(same_dst))
        srv_cnt = max(1, len(same_srv))
        dst_srv_cnt = max(1, len(same_dst_same_srv))

        same_srv_rate = float(dst_srv_cnt / dst_cnt)
        diff_srv_rate = float(1.0 - same_srv_rate)
        srv_diff_host_rate = float(len(same_srv_diff_dst) / srv_cnt) if srv_cnt > 0 else 0.0

        dst_host_count = min(255, max(1, dst_cnt))
        dst_host_srv_count = min(255, max(1, dst_srv_cnt))
        dst_host_same_srv_rate = float(dst_srv_cnt / dst_cnt)
        dst_host_diff_srv_rate = float(1.0 - dst_host_same_srv_rate)
        dst_host_same_src_port_rate = float(len(same_dst_same_src_port) / dst_cnt)
        dst_host_srv_diff_host_rate = srv_diff_host_rate

        return {
            "count": min(255, dst_cnt),
            "srv_count": min(255, srv_cnt),
            "same_srv_rate": same_srv_rate,
            "diff_srv_rate": diff_srv_rate,
            "srv_diff_host_rate": srv_diff_host_rate,
            "dst_host_count": dst_host_count,
            "dst_host_srv_count": dst_host_srv_count,
            "dst_host_same_srv_rate": dst_host_same_srv_rate,
            "dst_host_diff_srv_rate": dst_host_diff_srv_rate,
            "dst_host_same_src_port_rate": dst_host_same_src_port_rate,
            "dst_host_srv_diff_host_rate": dst_host_srv_diff_host_rate
        }

    def process_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        pkt_len: int,
        timestamp: float,
        tcp_flags: Optional[Dict[str, bool]] = None,
        win_size: int = 0,
        payload_len: int = 0
    ) -> List[Flow]:
        """
        Ingests a packet, updates stateful flow table, and flushes any expired flows.
        Returns list of expired flows ready for feature extraction & inference.
        """
        self.total_packets_processed += 1
        tcp_flags = tcp_flags or {}

        flow_key, is_forward = FlowKey.create(src_ip, dst_ip, src_port, dst_port, protocol)
        pkt_meta = PacketMetadata(
            timestamp=timestamp,
            length=pkt_len,
            is_forward=is_forward,
            tcp_flags=tcp_flags,
            win_size=win_size,
            payload_len=payload_len
        )

        expired_flows = []

        # Check for active flow or instantiate new
        if flow_key in self.active_flows:
            flow = self.active_flows[flow_key]
            flow.add_packet(pkt_meta)

            # Check if FIN / RST packet closes TCP flow immediately
            if tcp_flags.get("FIN", False) or tcp_flags.get("RST", False):
                exp = self.active_flows.pop(flow_key)
                self._record_flow_history(exp)
                expired_flows.append(exp)
        else:
            # Memory safety check: prevent unbounded active flow growth
            if len(self.active_flows) >= self.max_active_flows:
                logger.warning(f"Active flow table limit reached ({self.max_active_flows}). Flushing oldest idle flow.")
                oldest_key = min(self.active_flows.keys(), key=lambda k: self.active_flows[k].last_time)
                exp = self.active_flows.pop(oldest_key)
                self._record_flow_history(exp)
                expired_flows.append(exp)

            flow = Flow(key=flow_key, start_time=timestamp)
            flow.add_packet(pkt_meta)
            self.active_flows[flow_key] = flow
            self.total_flows_generated += 1

        # Check periodic flow timeouts
        timeouts = self.timeout_tracker.check_expired_flows(self.active_flows, timestamp)
        for t_flow in timeouts:
            if t_flow.key in self.active_flows:
                exp = self.active_flows.pop(t_flow.key)
                self._record_flow_history(exp)
                expired_flows.append(exp)

        return expired_flows

    def flush_all(self) -> List[Flow]:
        """
        Flushes all remaining active flows (used at end of PCAP replay / capture shutdown).
        """
        remaining = list(self.active_flows.values())
        for f in remaining:
            self._record_flow_history(f)
        self.active_flows.clear()
        return remaining
