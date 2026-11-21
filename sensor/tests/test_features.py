import pytest
from sensor.src.models.flow import FlowKey, Flow, PacketMetadata
from sensor.src.features.baseFeatures import BaseFeatureExtractor
from sensor.src.features.nslKddFeatures import NSLKDDFeatureMapper
from sensor.src.features.cicids2017Features import CICIDS2017FeatureMapper

def test_base_feature_extractor():
    key, _ = FlowKey.create("10.0.0.1", "10.0.0.2", 1234, 80, "tcp")
    flow = Flow(key=key, start_time=10.0)

    flow.add_packet(PacketMetadata(timestamp=10.0, length=100, is_forward=True, tcp_flags={"SYN": True}))
    flow.add_packet(PacketMetadata(timestamp=10.5, length=200, is_forward=False, tcp_flags={"ACK": True}))

    base = BaseFeatureExtractor.extract(flow)

    assert base["total_packets"] == 2
    assert base["fwd_packets"] == 1
    assert base["bwd_packets"] == 1
    assert base["total_bytes"] == 300
    assert base["fwd_bytes"] == 100
    assert base["bwd_bytes"] == 200
    assert base["duration"] == 0.5

def test_nsl_kdd_feature_mapper():
    key, _ = FlowKey.create("10.0.0.1", "10.0.0.2", 1234, 80, "tcp")
    flow = Flow(key=key, start_time=10.0)
    flow.add_packet(PacketMetadata(timestamp=10.0, length=100, is_forward=True, tcp_flags={"SYN": True}))

    features = NSLKDDFeatureMapper.map_flow(flow)

    assert features["protocol_type"] == "tcp"
    assert features["service"] == "http"
    assert features["flag"] in ["S0", "SF"]
    assert features["src_bytes"] == 100
    assert features["dst_bytes"] == 0
    assert features["hot"] == 0
    assert features["num_failed_logins"] == 0

def test_cicids2017_feature_mapper():
    key, _ = FlowKey.create("10.0.0.1", "10.0.0.2", 1234, 443, "tcp")
    flow = Flow(key=key, start_time=10.0)
    flow.add_packet(PacketMetadata(timestamp=10.0, length=100, is_forward=True, tcp_flags={"SYN": True}))
    flow.add_packet(PacketMetadata(timestamp=10.2, length=150, is_forward=False, tcp_flags={"ACK": True}))

    features = CICIDS2017FeatureMapper.map_flow(flow)

    assert features["Destination Port"] == 443
    assert features["Total Fwd Packets"] == 1
    assert features["Total Backward Packets"] == 1
    assert features["Total Length of Fwd Packets"] == 100
    assert features["Total Length of Bwd Packets"] == 150
    assert features["CWE Flag Count"] == 0
    assert features["SYN Flag Count"] == 1
