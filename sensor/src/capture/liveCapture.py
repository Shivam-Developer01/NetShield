import time
import threading
from typing import Callable, Optional
from scapy.all import AsyncSniffer, get_if_list
from sensor.src.capture.pcapReader import parse_scapy_packet
from sensor.src.utils.logger import get_logger

logger = get_logger("sensor-live-capture")

class LiveCaptureHandler:
    """
    Live network interface packet sniffer using Scapy AsyncSniffer.
    Gracefully handles driver/permission errors on Windows and Linux host environments.
    """
    def __init__(self, interface: str = "", packet_callback: Optional[Callable] = None):
        self.interface = interface
        self.packet_callback = packet_callback
        self.sniffer: Optional[AsyncSniffer] = None
        self.is_running: bool = False

    @staticmethod
    def list_available_interfaces():
        try:
            return get_if_list()
        except Exception as err:
            logger.warning(f"Could not list network interfaces: {err}")
            return []

    def start(self):
        if self.is_running:
            return

        available_ifaces = self.list_available_interfaces()
        logger.info(f"Available network interfaces: {available_ifaces}")

        if self.interface and self.interface not in available_ifaces:
            logger.warning(f"Configured interface '{self.interface}' not found in available interfaces. Proceeding with default sniffer bound.")

        def _on_pkt(pkt):
            parsed = parse_scapy_packet(pkt)
            if parsed is not None and self.packet_callback:
                self.packet_callback(parsed)

        try:
            kwargs = {"prn": _on_pkt, "store": False}
            if self.interface:
                kwargs["iface"] = self.interface

            self.sniffer = AsyncSniffer(**kwargs)
            self.sniffer.start()
            self.is_running = True
            logger.info(f"Live packet capture started on interface '{self.interface or 'default'}'")
        except PermissionError:
            logger.error("Permission denied: Live packet capture requires Administrator/root privileges or Npcap driver on Windows.")
            raise
        except Exception as err:
            logger.error(f"Failed to start live packet capture on '{self.interface}': {err}")
            raise

    def stop(self):
        if not self.is_running or not self.sniffer:
            return

        try:
            self.sniffer.stop()
            self.is_running = False
            logger.info("Live packet capture stopped cleanly.")
        except Exception as err:
            logger.warning(f"Error stopping sniffer: {err}")
