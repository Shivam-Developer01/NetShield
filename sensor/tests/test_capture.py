import os
import pytest
from scapy.all import IP, TCP, UDP, ICMP
from sensor.src.capture.pcapReader import parse_scapy_packet, PcapReaderHandler

def test_parse_scapy_valid_tcp_packet():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=1234, dport=80, flags="S", window=8192)
    pkt.time = 1000.0

    parsed = parse_scapy_packet(pkt)
    assert parsed is not None
    src_ip, dst_ip, src_port, dst_port, protocol, length, ts, flags, win, payload_len = parsed
    assert src_ip == "10.0.0.1"
    assert dst_ip == "10.0.0.2"
    assert src_port == 1234
    assert dst_port == 80
    assert protocol == "tcp"
    assert flags["SYN"] is True
    assert flags["ACK"] is False
    assert win == 8192

def test_parse_scapy_valid_udp_packet():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2")/UDP(sport=53, dport=5353)
    pkt.time = 1001.0

    parsed = parse_scapy_packet(pkt)
    assert parsed is not None
    assert parsed[4] == "udp"
    assert parsed[2] == 53
    assert parsed[3] == 5353

def test_parse_scapy_non_ip_packet():
    class RawNonIpPacket:
        def haslayer(self, cls):
            return False

    parsed = parse_scapy_packet(RawNonIpPacket())
    assert parsed is None

def test_pcap_reader_missing_file():
    handler = PcapReaderHandler("non_existent_file.pcap")
    with pytest.raises(FileNotFoundError):
        list(handler.read_packets())

def test_pcap_reader_sample_pcap():
    sample_path = os.path.join(os.path.dirname(__file__), "..", "samples", "sample_test.pcap")
    if os.path.exists(sample_path):
        handler = PcapReaderHandler(sample_path)
        pkts = list(handler.read_packets())
        assert len(pkts) == 10
