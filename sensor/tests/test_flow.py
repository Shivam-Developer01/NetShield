import pytest
from sensor.src.models.flow import FlowKey, Flow, PacketMetadata
from sensor.src.flow.flowManager import FlowManager

def test_flow_key_normalization():
    key1, is_fwd1 = FlowKey.create("192.168.1.1", "10.0.0.1", 80, 443, "TCP")
    key2, is_fwd2 = FlowKey.create("10.0.0.1", "192.168.1.1", 443, 80, "tcp")

    assert key1 == key2
    assert is_fwd1 != is_fwd2

def test_flow_packet_aggregation():
    key, _ = FlowKey.create("10.0.0.1", "10.0.0.2", 1000, 80, "tcp")
    flow = Flow(key=key, start_time=100.0)

    pkt1 = PacketMetadata(timestamp=100.0, length=60, is_forward=True, tcp_flags={"SYN": True}, win_size=8192)
    pkt2 = PacketMetadata(timestamp=100.1, length=60, is_forward=False, tcp_flags={"SYN": True, "ACK": True}, win_size=8192)

    flow.add_packet(pkt1)
    flow.add_packet(pkt2)

    assert flow.total_packets == 2
    assert flow.fwd_packets == 1
    assert flow.bwd_packets == 1
    assert flow.total_bytes == 120
    assert flow.fwd_bytes == 60
    assert flow.bwd_bytes == 60
    assert flow.syn_count == 2
    assert flow.ack_count == 1
    assert pytest.approx(flow.duration, 0.01) == 0.1

def test_flow_manager_timeout_and_flush():
    fm = FlowManager(timeout_seconds=5)

    # Packet at t=0
    expired = fm.process_packet("10.0.0.1", "10.0.0.2", 100, 80, "tcp", 60, 100.0)
    assert len(expired) == 0
    assert len(fm.active_flows) == 1

    # Packet at t=10 (exceeds 5s timeout)
    expired = fm.process_packet("10.0.0.3", "10.0.0.4", 200, 80, "tcp", 60, 110.0)
    assert len(expired) == 1
    assert expired[0].key.src_ip in ["10.0.0.1", "10.0.0.2"]

    # Flush remaining
    flushed = fm.flush_all()
    assert len(flushed) == 1
    assert len(fm.active_flows) == 0
