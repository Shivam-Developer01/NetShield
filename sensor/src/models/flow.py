import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Tuple, Optional

@dataclass(frozen=True)
class FlowKey:
    """
    Normalized 5-Tuple Key identifying a bidirectional network flow.
    src_ip, dst_ip, src_port, dst_port, protocol
    """
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    @classmethod
    def create(cls, ip1: str, ip2: str, port1: int, port2: int, proto: str) -> Tuple["FlowKey", bool]:
        """
        Creates a normalized FlowKey where (ip1, port1) <= (ip2, port2)
        to ensure forward and backward packets resolve to the exact same flow key.
        Returns: (flow_key, is_forward)
        """
        addr1 = (ip1, port1)
        addr2 = (ip2, port2)

        if addr1 <= addr2:
            return cls(src_ip=ip1, dst_ip=ip2, src_port=port1, dst_port=port2, protocol=proto.lower()), True
        else:
            return cls(src_ip=ip2, dst_ip=ip1, src_port=port2, dst_port=port1, protocol=proto.lower()), False


@dataclass
class PacketMetadata:
    timestamp: float
    length: int
    is_forward: bool
    tcp_flags: Dict[str, bool] = field(default_factory=dict)
    win_size: int = 0
    payload_len: int = 0


class Flow:
    """
    Stateful accumulator for a bidirectional network flow.
    Tracks statistics required for feature extraction.
    """
    def __init__(self, key: FlowKey, start_time: float):
        self.key = key
        self.start_time = start_time
        self.last_time = start_time

        self.fwd_packets: int = 0
        self.bwd_packets: int = 0
        self.fwd_bytes: int = 0
        self.bwd_bytes: int = 0

        self.fwd_pkt_lengths: List[int] = []
        self.bwd_pkt_lengths: List[int] = []
        self.pkt_lengths: List[int] = []

        self.fwd_timestamps: List[float] = []
        self.bwd_timestamps: List[float] = []
        self.all_timestamps: List[float] = []

        # TCP Flag Counters
        self.fin_count: int = 0
        self.syn_count: int = 0
        self.rst_count: int = 0
        self.psh_count: int = 0
        self.ack_count: int = 0
        self.urg_count: int = 0
        self.ece_count: int = 0
        self.cwr_count: int = 0

        self.fwd_psh_flags: int = 0
        self.fwd_urg_flags: int = 0
        self.bwd_psh_flags: int = 0
        self.bwd_urg_flags: int = 0

        self.init_win_bytes_fwd: int = 0
        self.init_win_bytes_bwd: int = 0

        self.service: str = "other"
        self.flag: str = "SF"

    def add_packet(self, pkt: PacketMetadata):
        self.last_time = pkt.timestamp
        self.pkt_lengths.append(pkt.length)
        self.all_timestamps.append(pkt.timestamp)

        if pkt.is_forward:
            self.fwd_packets += 1
            self.fwd_bytes += pkt.length
            self.fwd_pkt_lengths.append(pkt.length)
            self.fwd_timestamps.append(pkt.timestamp)
            if self.init_win_bytes_fwd == 0 and pkt.win_size > 0:
                self.init_win_bytes_fwd = pkt.win_size
            if pkt.tcp_flags.get("PSH", False):
                self.fwd_psh_flags += 1
            if pkt.tcp_flags.get("URG", False):
                self.fwd_urg_flags += 1
        else:
            self.bwd_packets += 1
            self.bwd_bytes += pkt.length
            self.bwd_pkt_lengths.append(pkt.length)
            self.bwd_timestamps.append(pkt.timestamp)
            if self.init_win_bytes_bwd == 0 and pkt.win_size > 0:
                self.init_win_bytes_bwd = pkt.win_size
            if pkt.tcp_flags.get("PSH", False):
                self.bwd_psh_flags += 1
            if pkt.tcp_flags.get("URG", False):
                self.bwd_urg_flags += 1

        # Global TCP Flag Counters
        if pkt.tcp_flags.get("FIN", False): self.fin_count += 1
        if pkt.tcp_flags.get("SYN", False): self.syn_count += 1
        if pkt.tcp_flags.get("RST", False): self.rst_count += 1
        if pkt.tcp_flags.get("PSH", False): self.psh_count += 1
        if pkt.tcp_flags.get("ACK", False): self.ack_count += 1
        if pkt.tcp_flags.get("URG", False): self.urg_count += 1
        if pkt.tcp_flags.get("ECE", False): self.ece_count += 1
        if pkt.tcp_flags.get("CWR", False): self.cwr_count += 1

    @property
    def duration(self) -> float:
        return max(0.0, self.last_time - self.start_time)

    @property
    def total_packets(self) -> int:
        return self.fwd_packets + self.bwd_packets

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes
