import os
from scapy.all import IP, TCP, UDP, ICMP, Ether, wrpcap

def create_sample_pcap(output_path=None):
    if output_path:
        pcap_path = os.path.abspath(output_path)
    else:
        # Robustly resolve sensor/samples/sample_test.pcap
        script_dir = os.path.dirname(os.path.abspath(__file__))
        out_dir = os.path.abspath(os.path.join(script_dir, "..", "samples"))
        os.makedirs(out_dir, exist_ok=True)
        pcap_path = os.path.join(out_dir, "sample_test.pcap")

    packets = []
    base_time = 1700000000.0

    # 1. Flow 1: Normal TCP HTTP 3-Way Handshake + Data
    pkt1 = IP(src="192.168.1.100", dst="192.168.1.1")/TCP(sport=49152, dport=80, flags="S", seq=1000, window=65535)
    pkt1.time = base_time

    pkt2 = IP(src="192.168.1.1", dst="192.168.1.100")/TCP(sport=80, dport=49152, flags="SA", seq=2000, ack=1001, window=65535)
    pkt2.time = base_time + 0.02

    pkt3 = IP(src="192.168.1.100", dst="192.168.1.1")/TCP(sport=49152, dport=80, flags="A", seq=1001, ack=2001, window=65535)
    pkt3.time = base_time + 0.03

    pkt4 = IP(src="192.168.1.100", dst="192.168.1.1")/TCP(sport=49152, dport=80, flags="PA", seq=1001, ack=2001, window=65535)/b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkt4.time = base_time + 0.05

    pkt5 = IP(src="192.168.1.1", dst="192.168.1.100")/TCP(sport=80, dport=49152, flags="PA", seq=2001, ack=1050, window=65535)/b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!"
    pkt5.time = base_time + 0.08

    pkt6 = IP(src="192.168.1.100", dst="192.168.1.1")/TCP(sport=49152, dport=80, flags="FA", seq=1050, ack=2050, window=65535)
    pkt6.time = base_time + 0.10

    packets.extend([pkt1, pkt2, pkt3, pkt4, pkt5, pkt6])

    # 2. Flow 2: UDP DNS Query / Response
    dns_query = IP(src="192.168.1.100", dst="192.168.1.1")/UDP(sport=53535, dport=53)/b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01"
    dns_query.time = base_time + 1.0

    dns_resp = IP(src="192.168.1.1", dst="192.168.1.100")/UDP(sport=53, dport=53535)/b"\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x93\x18\xf8\x50"
    dns_resp.time = base_time + 1.02

    packets.extend([dns_query, dns_resp])

    # 3. Flow 3: ICMP Ping Echo Request / Reply
    icmp_req = IP(src="192.168.1.100", dst="192.168.1.1")/ICMP(type=8, code=0)/b"PingData12345678"
    icmp_req.time = base_time + 2.0

    icmp_rep = IP(src="192.168.1.1", dst="192.168.1.100")/ICMP(type=0, code=0)/b"PingData12345678"
    icmp_rep.time = base_time + 2.01

    packets.extend([icmp_req, icmp_rep])

    wrpcap(pcap_path, packets)
    print(f"Sample PCAP generated at: {pcap_path} ({len(packets)} packets)")

if __name__ == "__main__":
    create_sample_pcap()
