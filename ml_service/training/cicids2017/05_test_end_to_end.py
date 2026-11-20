import os
import sys
import json
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.append(os.path.join(PROJECT_ROOT, "ml_service", "src", "features"))
sys.path.append(os.path.join(PROJECT_ROOT, "ml_service", "src", "preprocessing"))
sys.path.append(PROJECT_ROOT)

from sensor.src.models.flow import Flow, FlowKey, PacketMetadata
from sensor.src.features.cicids2017Features import CICIDS2017FeatureMapper
from sensor.src.features.nslKddFeatures import NSLKDDFeatureMapper
from sensor.src.flow.flowManager import FlowManager
from ml_service.src.inference.pipeline import get_inference_pipeline

def test_full_pipeline_flow():
    print("=" * 60)
    print("NETSHIELD PHASE 19.6 FULL END-TO-END PIPELINE TEST")
    print("=" * 60)
    
    # 1. Simulate packet stream into FlowManager
    print("\n[Step 1] Initializing FlowManager and feeding live packet stream...")
    fm = FlowManager(timeout_seconds=5)

    flags_syn = {"SYN": True, "ACK": False, "RST": False, "FIN": False, "PSH": False, "URG": False, "ECE": False, "CWR": False}
    flags_syn_ack = {"SYN": True, "ACK": True, "RST": False, "FIN": False, "PSH": False, "URG": False, "ECE": False, "CWR": False}
    flags_ack_psh = {"SYN": False, "ACK": True, "RST": False, "FIN": False, "PSH": True, "URG": False, "ECE": False, "CWR": False}

    fm.process_packet("192.168.1.105", "10.0.0.5", 55432, 80, "tcp", 64, 100.0, flags_syn, 8192)
    fm.process_packet("10.0.0.5", "192.168.1.105", 80, 55432, "tcp", 64, 100.02, flags_syn_ack, 8192)
    fm.process_packet("192.168.1.105", "10.0.0.5", 55432, 80, "tcp", 512, 100.05, flags_ack_psh, 8192)

    assert len(fm.active_flows) == 1, "Expected 1 active flow in FlowManager"
    flow = list(fm.active_flows.values())[0]
    assert flow is not None, "Flow failed to aggregate in FlowManager"
    print(f"  -> Successfully aggregated flow {str(flow.key)}: {flow.total_packets} packets, {flow.fwd_bytes + flow.bwd_bytes} bytes.")
    
    # 2. Extract Remediated Wire Features
    print("\n[Step 2] Extracting dynamic features with active/idle timers & rolling rates...")
    window_stats = fm.get_window_stats(flow)
    cic_features = CICIDS2017FeatureMapper.map_flow(flow)
    nsl_features = NSLKDDFeatureMapper.map_flow(flow, active_flows_count=len(fm.active_flows), window_stats=window_stats)
    
    print(f"  -> CICIDS2017 features generated: {len(cic_features)} keys (Active Mean: {cic_features['Active Mean']})")
    print(f"  -> NSL-KDD features generated   : {len(nsl_features)} keys (same_srv_rate: {nsl_features['same_srv_rate']})")
    
    # 3. Model Inference Pipeline
    print("\n[Step 3] Executing ML Model Inference on wire-extracted records...")
    pipeline = get_inference_pipeline()
    
    res_cic = pipeline.predict("cicids2017", [cic_features])
    res_nsl = pipeline.predict("nsl_kdd", [nsl_features])
    
    print(f"  -> CICIDS2017 Prediction: {res_cic['predictions'][0]['prediction']} (Confidence: {res_cic['predictions'][0]['confidence']:.4f})")
    print(f"  -> NSL-KDD Prediction   : {res_nsl['predictions'][0]['prediction']} (Confidence: {res_nsl['predictions'][0]['confidence']:.4f})")
    
    assert res_cic['predictions'][0]['confidence'] > 0.0, "Zero confidence returned from CICIDS2017 pipeline"
    assert res_nsl['predictions'][0]['confidence'] > 0.0, "Zero confidence returned from NSL-KDD pipeline"
    
    print("\n[Step 4] Sensor and ML inference contracts successfully verified!")

if __name__ == "__main__":
    test_full_pipeline_flow()
