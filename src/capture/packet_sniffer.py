"""
Passive Packet Capture Engine (Live Interface & PCAP Replay).
FR1 Compliant: Strictly passive downstream capture with 0 transmission back to source.
"""

import logging
import os
from typing import Callable, Optional

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import rdpcap, PcapReader, sniff, IP, IPv6, TCP, UDP, ICMP, Packet
from .malformed_handler import MalformedHandler

logger = logging.getLogger("TrafficPipeline.PacketSniffer")

class PassivePacketSniffer:
    def __init__(self, malformed_handler: Optional[MalformedHandler] = None, one_way_enforced: bool = True):
        self.malformed_handler = malformed_handler or MalformedHandler()
        self.one_way_enforced = one_way_enforced
        self.total_packets_captured = 0

    def process_raw_packet(self, packet: Packet, callback: Callable[[Packet], None]) -> None:
        """Enforces 1-way passive inspection & error boundary per packet."""
        try:
            # Strictly verify packet is IP/IPv6
            if not packet.haslayer(IP) and not packet.haslayer(IPv6):
                return  # Skip non-IP frames cleanly
            
            self.total_packets_captured += 1
            callback(packet)
        except Exception as e:
            raw_bytes = bytes(packet) if hasattr(packet, '__bytes__') else b''
            self.malformed_handler.handle_exception(raw_bytes, e, context="Packet Dissecting")

    def read_pcap(self, pcap_path: str, callback: Callable[[Packet], None]) -> int:
        """Replay packets from offline PCAP file."""
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        logger.info(f"Reading PCAP file: {pcap_path}")
        count = 0
        try:
            with PcapReader(pcap_path) as reader:
                for pkt in reader:
                    self.process_raw_packet(pkt, callback)
                    count += 1
        except Exception as e:
            logger.error(f"Error reading PCAP file '{pcap_path}': {e}")
            self.malformed_handler.handle_exception(b'', e, context=f"PCAP File Read ({pcap_path})")
            
        logger.info(f"Finished PCAP replay. Processed {count} packets.")
        return count

    def start_live_capture(self, interface: str, callback: Callable[[Packet], None], packet_count: int = 0, timeout: Optional[float] = None) -> None:
        """
        Starts live sniffing on specified interface.
        NOTE: Passive mode only. Socket is opened in read-only promiscuous mode.
        """
        logger.info(f"Starting passive live capture on interface '{interface}' (1-way enforced={self.one_way_enforced})...")
        
        def scapy_handler(pkt):
            self.process_raw_packet(pkt, callback)

        try:
            sniff(
                iface=interface,
                prn=scapy_handler,
                count=packet_count,
                timeout=timeout,
                store=0  # Memory efficient streaming
            )
        except Exception as e:
            logger.error(f"Live capture error on interface '{interface}': {e}")
            self.malformed_handler.handle_exception(b'', e, context=f"Live Sniff ({interface})")
