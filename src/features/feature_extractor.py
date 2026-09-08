"""
Feature Extraction Engine (FR3).
Extracts packet size statistics, inter-arrival timing, DNS features, TLS fingerprints, and fan-out metrics per flow.
"""

import math
import numpy as np
from typing import List, Dict, Any, Tuple, Optional
from scapy.all import Packet, IP, IPv6, TCP, UDP, DNS, DNSQR
from ..schema.flow_schema import FlowRecord
from .dns_analyzer import DNSAnalyzer
from .tls_analyzer import TLSAnalyzer

class FeatureExtractor:
    def __init__(self):
        self.dns_analyzer = DNSAnalyzer()
        self.tls_analyzer = TLSAnalyzer()

    def extract_features(
        self,
        flow_id: str,
        five_tuple: Tuple[str, str, int, int, str],
        packets_info: List[Dict[str, Any]],
        raw_packets: List[Packet],
        src_fanout_ips: int = 1,
        src_fanout_ports: int = 1,
        label: str = "benign"
    ) -> FlowRecord:
        """
        Calculates all FR3 flow-level features without decrypting payload.
        packets_info list contains dicts: {'timestamp': float, 'len': int, 'dir': 'fwd'/'bwd'}
        """
        src_ip, dst_ip, src_port, dst_port, protocol = five_tuple

        if not packets_info:
            raise ValueError(f"Cannot extract features from empty packet list for flow {flow_id}")

        timestamps = [p['timestamp'] for p in packets_info]
        sizes = [p['len'] for p in packets_info]
        dirs = [p['dir'] for p in packets_info]

        t_first = timestamps[0]
        t_last = timestamps[-1]
        duration = max(0.0, t_last - t_first)

        # Directional breakdown
        fwd_packets = sum(1 for d in dirs if d == 'fwd')
        bwd_packets = sum(1 for d in dirs if d == 'bwd')
        total_packets = len(packets_info)

        fwd_bytes = sum(sizes[i] for i in range(total_packets) if dirs[i] == 'fwd')
        bwd_bytes = sum(sizes[i] for i in range(total_packets) if dirs[i] == 'bwd')
        total_bytes = sum(sizes)

        # Rate metrics
        bytes_per_sec = round(total_bytes / duration, 4) if duration > 0 else float(total_bytes)
        packets_per_sec = round(total_packets / duration, 4) if duration > 0 else float(total_packets)

        # Packet size statistics
        pkt_size_min = int(min(sizes))
        pkt_size_max = int(max(sizes))
        pkt_size_mean = round(float(np.mean(sizes)), 4)
        pkt_size_std = round(float(np.std(sizes)), 4) if len(sizes) > 1 else 0.0

        # Inter-Arrival Timing (IAT)
        if len(timestamps) > 1:
            iats = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            iat_min = round(float(min(iats)), 6)
            iat_max = round(float(max(iats)), 6)
            iat_mean = round(float(np.mean(iats)), 6)
            iat_std = round(float(np.std(iats)), 6) if len(iats) > 1 else 0.0

            # Periodicity Score (Bounded 0 to 1 using coefficient of variation)
            if iat_mean > 0.0001:
                cv = iat_std / iat_mean  # Coefficient of variation
                periodicity_score = round(1.0 / (1.0 + cv), 4)
            else:
                periodicity_score = 0.0
        else:
            iat_min = 0.0
            iat_max = 0.0
            iat_mean = 0.0
            iat_std = 0.0
            periodicity_score = 0.0

        # DNS Query Extraction
        dns_queries = []
        for pkt in raw_packets:
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                try:
                    qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                    if qname:
                        dns_queries.append(qname)
                except Exception:
                    pass

        dns_features = self.dns_analyzer.analyze_queries(dns_queries)

        # TLS / JA3 Extraction
        tls_features = self.tls_analyzer.extract_tls_info(raw_packets)

        # Bytes Ratio
        bytes_ratio = round(fwd_bytes / max(1, bwd_bytes), 4)

        return FlowRecord(
            flow_id=flow_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            timestamp_first=round(t_first, 6),
            timestamp_last=round(t_last, 6),
            duration=round(duration, 6),
            fwd_packets=fwd_packets,
            bwd_packets=bwd_packets,
            total_packets=total_packets,
            fwd_bytes=fwd_bytes,
            bwd_bytes=bwd_bytes,
            total_bytes=total_bytes,
            bytes_per_sec=bytes_per_sec,
            packets_per_sec=packets_per_sec,
            pkt_size_min=pkt_size_min,
            pkt_size_max=pkt_size_max,
            pkt_size_mean=pkt_size_mean,
            pkt_size_std=pkt_size_std,
            iat_min=iat_min,
            iat_max=iat_max,
            iat_mean=iat_mean,
            iat_std=iat_std,
            periodicity_score=periodicity_score,
            dns_query_count=dns_features["dns_query_count"],
            dns_mean_entropy=dns_features["dns_mean_entropy"],
            dns_max_entropy=dns_features["dns_max_entropy"],
            dns_mean_length=dns_features["dns_mean_length"],
            dns_ngram_score=dns_features["dns_ngram_score"],
            dns_tunneling_flag=dns_features["dns_tunneling_flag"],
            has_tls=tls_features["has_tls"],
            sni_domain=tls_features["sni_domain"],
            ja3_fingerprint=tls_features["ja3_fingerprint"],
            ja3s_fingerprint=tls_features["ja3s_fingerprint"],
            tls_version=tls_features["tls_version"],
            cipher_suites_count=tls_features["cipher_suites_count"],
            src_fanout_dst_ips_1m=src_fanout_ips,
            src_fanout_dst_ports_1m=src_fanout_ports,
            bytes_ratio_fwd_bwd=bytes_ratio,
            label=label
        )
