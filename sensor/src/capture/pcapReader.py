import os
from typing import Generator, Tuple, Optional, Dict, Any
from scapy.all import rdpcap, PcapReader, IP, IPv6, TCP, UDP, ICMP
from sensor.src.utils.logger import get_logger

logger = get_logger("sensor-pcap-reader")

def parse_scapy_packet(pkt) -> Optional[Tuple[str, str, int, int, str, int, float, Dict[str, bool], int, int]]:
    """
    Safely extracts 5-tuple metadata from a Scapy packet object.
    Returns: (src_ip, dst_ip, src_port, dst_port, protocol, length, timestamp, tcp_flags, win_size, payload_len)
    or None if non-IP or malformed.
    """
    try:
        if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
            return None

        ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)

        protocol = "other"
        src_port = 0
        dst_port = 0
        tcp_flags = {}
        win_size = 0
        payload_len = 0

        if pkt.haslayer(TCP):
            protocol = "tcp"
            tcp_layer = pkt[TCP]
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            win_size = int(tcp_layer.window)
            payload_len = len(tcp_layer.payload)

            flags_int = int(tcp_layer.flags)
            tcp_flags = {
                "FIN": bool(flags_int & 0x01),
                "SYN": bool(flags_int & 0x02),
                "RST": bool(flags_int & 0x04),
                "PSH": bool(flags_int & 0x08),
                "ACK": bool(flags_int & 0x10),
                "URG": bool(flags_int & 0x20),
                "ECE": bool(flags_int & 0x40),
                "CWR": bool(flags_int & 0x80)
            }
        elif pkt.haslayer(UDP):
            protocol = "udp"
            udp_layer = pkt[UDP]
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)
            payload_len = len(udp_layer.payload)
        elif pkt.haslayer(ICMP):
            protocol = "icmp"

        pkt_len = len(pkt)
        timestamp = float(pkt.time)

        return src_ip, dst_ip, src_port, dst_port, protocol, pkt_len, timestamp, tcp_flags, win_size, payload_len
    except Exception as err:
        logger.debug(f"Failed to parse packet: {err}")
        return None


class PcapReaderHandler:
    """
    Reads packets deterministically from a PCAP file without requiring root/driver privileges.
    """
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path

    def read_packets(self) -> Generator[Tuple[str, str, int, int, str, int, float, Dict[str, bool], int, int], None, None]:
        if not os.path.exists(self.pcap_path):
            raise FileNotFoundError(f"PCAP file not found at: {self.pcap_path}")

        logger.info(f"Opening PCAP file for replay: {self.pcap_path}")
        parsed_count = 0
        malformed_count = 0

        try:
            with PcapReader(self.pcap_path) as pcap_reader:
                for pkt in pcap_reader:
                    parsed = parse_scapy_packet(pkt)
                    if parsed is not None:
                        parsed_count += 1
                        yield parsed
                    else:
                        malformed_count += 1
        except Exception as err:
            logger.error(f"Error reading PCAP stream from {self.pcap_path}: {err}")
            raise

        logger.info(f"PCAP replay completed. Total parsed IP packets: {parsed_count}, Ignored/Non-IP: {malformed_count}")
