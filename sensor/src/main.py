import os
import sys
import time
import argparse
import signal
from typing import Dict, Any, List

from sensor.src.config.settings import get_settings, SensorSettings
from sensor.src.utils.logger import get_logger
from sensor.src.flow.flowManager import FlowManager
from sensor.src.features.nslKddFeatures import NSLKDDFeatureMapper
from sensor.src.features.cicids2017Features import CICIDS2017FeatureMapper
from sensor.src.features.featureValidator import FeatureValidator
from sensor.src.inference.mlClient import SensorMLClient
from sensor.src.capture.pcapReader import PcapReaderHandler
from sensor.src.capture.liveCapture import LiveCaptureHandler

logger = get_logger("netshield-sensor-cli")

class NetworkSensorApp:
    def __init__(self, settings: SensorSettings):
        self.settings = settings
        self.flow_manager = FlowManager(
            timeout_seconds=settings.flow_timeout_seconds,
            max_active_flows=settings.max_active_flows
        )
        self.ml_client = SensorMLClient(
            backend_url=settings.backend_url,
            ml_service_url=settings.ml_service_url,
            timeout_ms=settings.request_timeout_ms,
            service_token=settings.sensor_service_token
        )
        self.is_running = False

        # Statistics
        self.stats = {
            "packets_captured": 0,
            "flows_generated": 0,
            "flows_processed": 0,
            "flows_rejected": 0,
            "predictions_sent": 0,
            "errors": 0
        }

    def send_telemetry(self) -> bool:
        """
        Dispatches current operational telemetry and heartbeat to backend.
        """
        payload = {
            "packetsProcessed": self.stats["packets_captured"],
            "flowsCreated": self.stats["flows_generated"],
            "activeFlows": len(self.flow_manager.active_flows),
            "validationFailures": self.stats["flows_rejected"],
            "predictionsSent": self.stats["predictions_sent"],
            "errors": self.stats["errors"],
            "mode": self.settings.sensor_mode,
            "datasetType": self.settings.dataset_type,
            "status": "healthy"
        }
        return self.ml_client.send_telemetry(payload)

    def process_flow(self, flow) -> bool:
        """
        Maps flow to dataset schema, validates, and sends prediction request.
        """
        self.stats["flows_processed"] += 1
        dataset_key = self.settings.dataset_type.lower().replace("-", "_")

        # 1. Map flow features
        if dataset_key == "nsl_kdd":
            raw_features = NSLKDDFeatureMapper.map_flow(flow, active_flows_count=len(self.flow_manager.active_flows)+1)
        else:
            raw_features = CICIDS2017FeatureMapper.map_flow(flow)

        # 2. Validate feature schema
        is_valid, error_msg = FeatureValidator.validate(raw_features, dataset_key)
        if not is_valid:
            self.stats["flows_rejected"] += 1
            logger.warning(f"Flow {flow.key.src_ip}:{flow.key.src_port} -> {flow.key.dst_ip}:{flow.key.dst_port} REJECTED: {error_msg}")
            return False

        # 3. Transmit to backend/ML
        flow_source_info = {
            "sensor": "NetShield-Scapy-Sensor",
            "src_ip": flow.key.src_ip,
            "dst_ip": flow.key.dst_ip,
            "src_port": flow.key.src_port,
            "dst_port": flow.key.dst_port,
            "protocol": flow.key.protocol.upper(),
            "flow_id": f"{flow.key.src_ip}:{flow.key.src_port}->{flow.key.dst_ip}:{flow.key.dst_port}_{flow.key.protocol.upper()}"
        }
        success, response = self.ml_client.send_prediction(dataset_key, raw_features, source_info=flow_source_info)
        if success:
            self.stats["predictions_sent"] += 1
            pred_label = response.get("predictions", [{}])[0].get("prediction", "Unknown") if "predictions" in response else "Processed"
            logger.info(f"[Prediction Sent] Flow ({flow.key.src_ip} -> {flow.key.dst_ip}): Prediction='{pred_label}'")
            return True
        else:
            self.stats["errors"] += 1
            logger.error(f"Failed prediction delivery for flow ({flow.key.src_ip} -> {flow.key.dst_ip}): {response}")
            return False

    def run_pcap(self, pcap_path: str):
        logger.info(f"Starting PCAP Mode analysis on: {pcap_path}")
        handler = PcapReaderHandler(pcap_path)

        for pkt_tuple in handler.read_packets():
            self.stats["packets_captured"] += 1
            src_ip, dst_ip, src_port, dst_port, protocol, length, timestamp, tcp_flags, win_size, payload_len = pkt_tuple

            expired_flows = self.flow_manager.process_packet(
                src_ip, dst_ip, src_port, dst_port, protocol,
                length, timestamp, tcp_flags, win_size, payload_len
            )
            for flow in expired_flows:
                self.process_flow(flow)

        # Flush active flows upon PCAP completion
        flushed_flows = self.flow_manager.flush_all()
        for flow in flushed_flows:
            self.process_flow(flow)

        self.stats["flows_generated"] = self.flow_manager.total_flows_generated

    def run_live(self, interface: str):
        logger.info(f"Starting Live Mode capture on interface: '{interface or 'default'}'")
        self.is_running = True

        def pkt_callback(pkt_tuple):
            if not self.is_running:
                return
            self.stats["packets_captured"] += 1
            src_ip, dst_ip, src_port, dst_port, protocol, length, timestamp, tcp_flags, win_size, payload_len = pkt_tuple

            expired_flows = self.flow_manager.process_packet(
                src_ip, dst_ip, src_port, dst_port, protocol,
                length, timestamp, tcp_flags, win_size, payload_len
            )
            for flow in expired_flows:
                self.process_flow(flow)

        handler = LiveCaptureHandler(interface=interface, packet_callback=pkt_callback)
        handler.start()

        try:
            while self.is_running:
                time.sleep(1.0)
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received. Stopping live capture...")
        finally:
            handler.stop()
            flushed_flows = self.flow_manager.flush_all()
            for flow in flushed_flows:
                self.process_flow(flow)
            self.stats["flows_generated"] = self.flow_manager.total_flows_generated

    def print_summary(self):
        banner = f"""
============================================================
NETSHIELD NETWORK SENSOR
============================================================
Mode:               {self.settings.sensor_mode.upper()}
Dataset Target:     {self.settings.dataset_type.upper()}
Packets Captured:   {self.stats['packets_captured']}
Flows Generated:    {self.stats['flows_generated']}
Flows Processed:    {self.stats['flows_processed']}
Flows Rejected:     {self.stats['flows_rejected']}
Predictions Sent:   {self.stats['predictions_sent']}
Errors:             {self.stats['errors']}
============================================================
"""
        print(banner)


def main():
    parser = argparse.ArgumentParser(description="NetShield Network Sensor CLI")
    parser.add_argument("--mode", choices=["pcap", "live"], help="Capture mode: pcap or live")
    parser.add_argument("--file", help="Path to PCAP file (PCAP mode)")
    parser.add_argument("--interface", help="Network interface name (Live mode)")
    parser.add_argument("--dataset", choices=["nsl_kdd", "cicids2017"], help="Target ML dataset schema")
    args = parser.parse_args()

    settings = get_settings()
    if args.mode:
        settings.sensor_mode = args.mode
    if args.file:
        settings.pcap_file = args.file
    if args.interface:
        settings.sensor_interface = args.interface
    if args.dataset:
        settings.dataset_type = args.dataset

    app = NetworkSensorApp(settings)
    if not app.ml_client.service_token:
        app.ml_client.authenticate_sensor()

    def signal_handler(sig, frame):
        logger.info("Signal received. Shutting down sensor...")
        app.is_running = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        if settings.sensor_mode == "pcap":
            app.is_running = True
            app.run_pcap(settings.pcap_file)
            app.print_summary()
            app.send_telemetry()
            logger.info("PCAP processing complete. Entering active telemetry heartbeat loop (interval: 15s)...")
            while app.is_running:
                time.sleep(15)
                if app.is_running:
                    app.send_telemetry()
        else:
            app.run_live(settings.sensor_interface)
    except KeyboardInterrupt:
        logger.info("Interrupted by user. Exiting...")
    except Exception as err:
        logger.error(f"Sensor execution failed: {err}")
    finally:
        app.print_summary()


if __name__ == "__main__":
    main()
