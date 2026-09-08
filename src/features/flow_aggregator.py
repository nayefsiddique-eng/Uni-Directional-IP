"""
Flow Reconstruction & Aggregation Engine (FR2).
Maintains 5-tuple session states, tracks bi-directional packets, sliding fan-out windows, and emits completed flows.
"""

import hashlib
import time
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Callable
from scapy.all import Packet, IP, IPv6, TCP, UDP, ICMP
from ..schema.flow_schema import FlowRecord
from .feature_extractor import FeatureExtractor

class FlowAggregator:
    def __init__(
        self,
        inactivity_timeout: float = 5.0,
        active_timeout: float = 60.0,
        fanout_window: float = 60.0
    ):
        self.inactivity_timeout = inactivity_timeout
        self.active_timeout = active_timeout
        self.fanout_window = fanout_window
        self.feature_extractor = FeatureExtractor()

        # Key: canonical 5-tuple string -> flow state dict
        self.active_flows: Dict[str, Dict] = {}

        # Fan-out tracking: src_ip -> list of (timestamp, dst_ip, dst_port)
        self.fanout_tracker: Dict[str, List[Tuple[float, str, int]]] = defaultdict(list)

    @staticmethod
    def get_canonical_tuple(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str) -> Tuple[Tuple[str, str, int, int, str], bool]:
        """
        Normalizes 5-tuple so that (A, B, pA, pB, Proto) and (B, A, pB, pA, Proto) map to the same key.
        Returns ((norm_src, norm_dst, norm_sport, norm_dport, proto), is_forward)
        """
        key1 = (src_ip, src_port)
        key2 = (dst_ip, dst_port)

        if key1 <= key2:
            return (src_ip, dst_ip, src_port, dst_port, proto), True
        else:
            return (dst_ip, src_ip, dst_port, src_port, proto), False

    @staticmethod
    def get_flow_hash(five_tuple: Tuple[str, str, int, int, str]) -> str:
        s = f"{five_tuple[0]}:{five_tuple[2]}-{five_tuple[1]}:{five_tuple[3]}-{five_tuple[4]}"
        return hashlib.md5(s.encode('utf-8')).hexdigest()[:16]

    def add_packet(self, packet: Packet, label: str = "benign", current_time: Optional[float] = None) -> Optional[FlowRecord]:
        """
        Ingests a single packet into flow tracking.
        Returns a FlowRecord if adding this packet forced a flow completion/flush, else None.
        """
        if not packet.haslayer(IP) and not packet.haslayer(IPv6):
            return None

        pkt_time = float(packet.time) if hasattr(packet, 'time') and packet.time else (current_time or time.time())

        # Extract 5-tuple fields
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        else:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst

        src_port = 0
        dst_port = 0
        proto = "OTHER"

        if packet.haslayer(TCP):
            proto = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            proto = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            proto = "ICMP"

        five_tuple, is_fwd = self.get_canonical_tuple(src_ip, dst_ip, src_port, dst_port, proto)
        flow_key = f"{five_tuple[0]}_{five_tuple[1]}_{five_tuple[2]}_{five_tuple[3]}_{five_tuple[4]}"

        # Update fan-out tracker for actual packet source IP
        self.fanout_tracker[src_ip].append((pkt_time, dst_ip, dst_port))

        pkt_len = len(packet)
        direction = "fwd" if is_fwd else "bwd"

        # Check if flow already exists
        flushed_flow = None
        if flow_key in self.active_flows:
            flow_state = self.active_flows[flow_key]
            
            # Check active timeout
            if pkt_time - flow_state['t_start'] >= self.active_timeout:
                flushed_flow = self._finalize_flow(flow_key, pkt_time)
                self._init_flow(flow_key, five_tuple, pkt_time, pkt_len, direction, packet, label)
            else:
                flow_state['t_last'] = pkt_time
                flow_state['packets_info'].append({'timestamp': pkt_time, 'len': pkt_len, 'dir': direction})
                flow_state['raw_packets'].append(packet)
                if label != "benign":
                    flow_state['label'] = label
        else:
            self._init_flow(flow_key, five_tuple, pkt_time, pkt_len, direction, packet, label)

        return flushed_flow

    def _init_flow(self, flow_key: str, five_tuple: Tuple, pkt_time: float, pkt_len: int, direction: str, packet: Packet, label: str):
        self.active_flows[flow_key] = {
            'five_tuple': five_tuple,
            't_start': pkt_time,
            't_last': pkt_time,
            'packets_info': [{'timestamp': pkt_time, 'len': pkt_len, 'dir': direction}],
            'raw_packets': [packet],
            'label': label
        }

    def _calculate_fanout(self, src_ip: str, current_time: float) -> Tuple[int, int]:
        """Calculates unique dst IPs and unique dst ports for src_ip within fanout_window."""
        cutoff = current_time - self.fanout_window
        # Prune old entries
        self.fanout_tracker[src_ip] = [entry for entry in self.fanout_tracker[src_ip] if entry[0] >= cutoff]

        entries = self.fanout_tracker[src_ip]
        unique_ips = len(set(e[1] for e in entries))
        unique_ports = len(set(e[2] for e in entries))
        return unique_ips, unique_ports

    def _finalize_flow(self, flow_key: str, current_time: float) -> FlowRecord:
        state = self.active_flows.pop(flow_key)
        five_tuple = state['five_tuple']
        flow_id = self.get_flow_hash(five_tuple)
        src_ip = five_tuple[0]

        fanout_ips, fanout_ports = self._calculate_fanout(src_ip, current_time)

        return self.feature_extractor.extract_features(
            flow_id=flow_id,
            five_tuple=five_tuple,
            packets_info=state['packets_info'],
            raw_packets=state['raw_packets'],
            src_fanout_ips=fanout_ips,
            src_fanout_ports=fanout_ports,
            label=state['label']
        )

    def check_timeouts(self, current_time: float) -> List[FlowRecord]:
        """Flushes flows that have exceeded inactivity_timeout or active_timeout."""
        expired_keys = []
        for key, state in list(self.active_flows.items()):
            if (current_time - state['t_last'] >= self.inactivity_timeout) or \
               (current_time - state['t_start'] >= self.active_timeout):
                expired_keys.append(key)

        return [self._finalize_flow(k, current_time) for k in expired_keys]

    def flush_all(self) -> List[FlowRecord]:
        """Flushes all remaining active flows (e.g. at end of PCAP or shutdown)."""
        current_time = time.time()
        keys = list(self.active_flows.keys())
        return [self._finalize_flow(k, current_time) for k in keys]
