import os
import sys
import json

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.append(os.path.join(PROJECT_ROOT, "ml_service", "src", "features"))
sys.path.append(os.path.join(PROJECT_ROOT, "ml_service", "src", "preprocessing"))
sys.path.append(PROJECT_ROOT)

from ml_service.src.inference.pipeline import get_inference_pipeline
from sensor.src.models.flow import Flow, FlowKey, PacketMetadata
from sensor.src.features.cicids2017Features import CICIDS2017FeatureMapper
from sensor.src.features.nslKddFeatures import NSLKDDFeatureMapper

def test_sensor_to_inference():
    print("=" * 60)
    print("TESTING SENSOR-TO-INFERENCE PIPELINE COMPATIBILITY")
    print("=" * 60)
    
    key = FlowKey(
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=80,
        protocol="tcp"
    )
    flow = Flow(key=key, start_time=100.0)
    flow.add_packet(PacketMetadata(
        timestamp=100.01,
        length=64,
        is_forward=True,
        tcp_flags={"SYN": True, "ACK": False, "RST": False, "FIN": False, "PSH": False, "URG": False, "ECE": False, "CWR": False},
        win_size=8192
    ))
    flow.add_packet(PacketMetadata(
        timestamp=100.02,
        length=64,
        is_forward=False,
        tcp_flags={"SYN": True, "ACK": True, "RST": False, "FIN": False, "PSH": False, "URG": False, "ECE": False, "CWR": False},
        win_size=8192
    ))
    flow.add_packet(PacketMetadata(
        timestamp=100.03,
        length=128,
        is_forward=True,
        tcp_flags={"SYN": False, "ACK": True, "RST": False, "FIN": False, "PSH": True, "URG": False, "ECE": False, "CWR": False},
        win_size=8192
    ))
    
    cic_dict = CICIDS2017FeatureMapper.map_flow(flow)
    nsl_dict = NSLKDDFeatureMapper.map_flow(flow, active_flows_count=5)
    
    pipeline = get_inference_pipeline()
    
    # Test CICIDS2017 prediction
    res_cic = pipeline.predict("cicids2017", [cic_dict])
    print("\nCICIDS2017 Prediction on Sensor Flow:")
    print(f"  - Prediction: {res_cic['predictions'][0]['prediction']}")
    print(f"  - Confidence: {res_cic['predictions'][0]['confidence']:.4f}")
    
    # Test NSL-KDD prediction
    res_nsl = pipeline.predict("nsl_kdd", [nsl_dict])
    print("\nNSL-KDD Prediction on Sensor Flow:")
    print(f"  - Prediction: {res_nsl['predictions'][0]['prediction']}")
    print(f"  - Confidence: {res_nsl['predictions'][0]['confidence']:.4f}")
    
    print("\nSUCCESS: Sensor features successfully pass through production inference pipelines without crashing.")

if __name__ == "__main__":
    test_sensor_to_inference()
