from typing import Dict, Any
from sensor.src.models.flow import Flow
from sensor.src.features.baseFeatures import BaseFeatureExtractor

class CICIDS2017FeatureMapper:
    """
    Transforms raw flow statistics into exact 78-raw-feature dictionary expected by CICIDS2017 preprocessor.
    """
    @staticmethod
    def map_flow(flow: Flow) -> Dict[str, Any]:
        base = BaseFeatureExtractor.extract(flow)

        pkt_len = base["pkt_len_stats"]
        fwd_len = base["fwd_pkt_len_stats"]
        bwd_len = base["bwd_pkt_len_stats"]

        flow_iat = base["flow_iat_stats"]
        fwd_iat = base["fwd_iat_stats"]
        bwd_iat = base["bwd_iat_stats"]

        fwd_header_len = flow.fwd_packets * 20
        bwd_header_len = flow.bwd_packets * 20

        pkt_var = (pkt_len["std"] ** 2)

        return {
            "Destination Port": flow.key.dst_port,
            "Flow Duration": int(round(base["duration_us"])),
            "Total Fwd Packets": flow.fwd_packets,
            "Total Backward Packets": flow.bwd_packets,
            "Total Length of Fwd Packets": flow.fwd_bytes,
            "Total Length of Bwd Packets": flow.bwd_bytes,
            "Fwd Packet Length Max": fwd_len["max"],
            "Fwd Packet Length Min": fwd_len["min"],
            "Fwd Packet Length Mean": fwd_len["mean"],
            "Fwd Packet Length Std": fwd_len["std"],
            "Bwd Packet Length Max": bwd_len["max"],
            "Bwd Packet Length Min": bwd_len["min"],
            "Bwd Packet Length Mean": bwd_len["mean"],
            "Bwd Packet Length Std": bwd_len["std"],
            "Flow Bytes/s": base["flow_bytes_per_sec"],
            "Flow Packets/s": base["flow_packets_per_sec"],
            "Flow IAT Mean": flow_iat["mean"],
            "Flow IAT Std": flow_iat["std"],
            "Flow IAT Max": flow_iat["max"],
            "Flow IAT Min": flow_iat["min"],
            "Fwd IAT Total": base["fwd_iat_total_us"],
            "Fwd IAT Mean": fwd_iat["mean"],
            "Fwd IAT Std": fwd_iat["std"],
            "Fwd IAT Max": fwd_iat["max"],
            "Fwd IAT Min": fwd_iat["min"],
            "Bwd IAT Total": base["bwd_iat_total_us"],
            "Bwd IAT Mean": bwd_iat["mean"],
            "Bwd IAT Std": bwd_iat["std"],
            "Bwd IAT Max": bwd_iat["max"],
            "Bwd IAT Min": bwd_iat["min"],
            "Fwd PSH Flags": base["fwd_psh_flags"],
            "Fwd URG Flags": base["fwd_urg_flags"],
            "Bwd PSH Flags": base["bwd_psh_flags"],
            "Bwd URG Flags": base["bwd_urg_flags"],
            "Fwd Header Length": fwd_header_len,
            "Bwd Header Length": bwd_header_len,
            "Fwd Packets/s": base["fwd_packets_per_sec"],
            "Bwd Packets/s": base["bwd_packets_per_sec"],
            "Min Packet Length": pkt_len["min"],
            "Max Packet Length": pkt_len["max"],
            "Packet Length Mean": pkt_len["mean"],
            "Packet Length Std": pkt_len["std"],
            "Packet Length Variance": pkt_var,
            "FIN Flag Count": base["fin_count"],
            "SYN Flag Count": base["syn_count"],
            "RST Flag Count": base["rst_count"],
            "PSH Flag Count": base["psh_count"],
            "ACK Flag Count": base["ack_count"],
            "URG Flag Count": base["urg_count"],
            "CWE Flag Count": 0,
            "ECE Flag Count": base["ece_count"],
            "CWR Flag Count": base["cwr_count"],
            "Down/Up Ratio": base["down_up_ratio"],
            "Average Packet Size": pkt_len["mean"],
            "Avg Fwd Segment Size": fwd_len["mean"],
            "Avg Bwd Segment Size": bwd_len["mean"],
            "Fwd Header Length.1": fwd_header_len,
            "Fwd Avg Bytes/Bulk": 0,
            "Fwd Avg Packets/Bulk": 0,
            "Fwd Avg Bulk Rate": 0,
            "Bwd Avg Bytes/Bulk": 0,
            "Bwd Avg Packets/Bulk": 0,
            "Bwd Avg Bulk Rate": 0,
            "Subflow Fwd Packets": flow.fwd_packets,
            "Subflow Fwd Bytes": flow.fwd_bytes,
            "Subflow Bwd Packets": flow.bwd_packets,
            "Subflow Bwd Bytes": flow.bwd_bytes,
            "Init_Win_bytes_forward": base["init_win_bytes_fwd"],
            "Init_Win_bytes_backward": base["init_win_bytes_bwd"],
            "act_data_pkt_fwd": max(0, flow.fwd_packets - 1),
            "min_seg_size_forward": 20,
            "Active Mean": base["active_stats"]["mean"],
            "Active Std": base["active_stats"]["std"],
            "Active Max": base["active_stats"]["max"],
            "Active Min": base["active_stats"]["min"],
            "Idle Mean": base["idle_stats"]["mean"],
            "Idle Std": base["idle_stats"]["std"],
            "Idle Max": base["idle_stats"]["max"],
            "Idle Min": base["idle_stats"]["min"]
        }
