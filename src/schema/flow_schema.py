"""
Flow Record Schema Definition for Handoff to AI/ML Module.
Contains dataclass definition, serialization methods, and schema field metadata.
"""

from dataclasses import dataclass, asdict, field
from typing import Dict, Any, Optional
import json

@dataclass
class FlowRecord:
    # 5-tuple Identifiers & Timestamps
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # TCP, UDP, ICMP, OTHER
    timestamp_first: float
    timestamp_last: float
    duration: float  # seconds

    # Volume & Rate Metrics
    fwd_packets: int
    bwd_packets: int
    total_packets: int
    fwd_bytes: int
    bwd_bytes: int
    total_bytes: int
    bytes_per_sec: float
    packets_per_sec: float

    # Packet Size Distribution (FR3)
    pkt_size_min: int
    pkt_size_max: int
    pkt_size_mean: float
    pkt_size_std: float

    # Inter-Arrival Timing & Periodicity (FR3)
    iat_min: float
    iat_max: float
    iat_mean: float
    iat_std: float
    periodicity_score: float  # 0.0 to 1.0 (1.0 = highly periodic / beaconing)

    # DNS Query Features (FR3)
    dns_query_count: int
    dns_mean_entropy: float
    dns_max_entropy: float
    dns_mean_length: float
    dns_ngram_score: float
    dns_tunneling_flag: bool

    # TLS Handshake Metadata & Fingerprinting (FR3)
    has_tls: bool
    sni_domain: str
    ja3_fingerprint: str
    ja3s_fingerprint: str
    tls_version: str
    cipher_suites_count: int

    # Connection Fan-Out & Ratio Metrics (FR3)
    src_fanout_dst_ips_1m: int
    src_fanout_dst_ports_1m: int
    bytes_ratio_fwd_bwd: float

    # Ground Truth Label for Training & Testing (FR5/FR6)
    label: str = "benign"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FlowRecord':
        return cls(**data)


def get_schema_metadata() -> Dict[str, Any]:
    """Returns field name, type, and unit description for documentation agreement."""
    return {
        "flow_id": {"type": "str", "description": "Bi-directional 5-tuple hash identifier"},
        "src_ip": {"type": "str", "description": "Source IP address"},
        "dst_ip": {"type": "str", "description": "Destination IP address"},
        "src_port": {"type": "int", "description": "Source port number"},
        "dst_port": {"type": "int", "description": "Destination port number"},
        "protocol": {"type": "str", "description": "Transport protocol (TCP/UDP/ICMP)"},
        "timestamp_first": {"type": "float", "description": "Epoch timestamp of first packet (sec)"},
        "timestamp_last": {"type": "float", "description": "Epoch timestamp of last packet (sec)"},
        "duration": {"type": "float", "description": "Total flow duration (sec)"},
        "fwd_packets": {"type": "int", "description": "Packets in forward direction (src -> dst)"},
        "bwd_packets": {"type": "int", "description": "Packets in backward direction (dst -> src)"},
        "total_packets": {"type": "int", "description": "Total packets in flow"},
        "fwd_bytes": {"type": "int", "description": "Payload/frame bytes in forward direction"},
        "bwd_bytes": {"type": "int", "description": "Payload/frame bytes in backward direction"},
        "total_bytes": {"type": "int", "description": "Total bytes in flow"},
        "bytes_per_sec": {"type": "float", "description": "Byte transfer rate"},
        "packets_per_sec": {"type": "float", "description": "Packet rate"},
        "pkt_size_min": {"type": "int", "description": "Minimum packet size (bytes)"},
        "pkt_size_max": {"type": "int", "description": "Maximum packet size (bytes)"},
        "pkt_size_mean": {"type": "float", "description": "Mean packet size (bytes)"},
        "pkt_size_std": {"type": "float", "description": "Standard deviation of packet size"},
        "iat_min": {"type": "float", "description": "Minimum inter-arrival time (sec)"},
        "iat_max": {"type": "float", "description": "Maximum inter-arrival time (sec)"},
        "iat_mean": {"type": "float", "description": "Mean inter-arrival time (sec)"},
        "iat_std": {"type": "float", "description": "Standard deviation of IAT"},
        "periodicity_score": {"type": "float", "description": "Normalized periodicity metric (0 to 1)"},
        "dns_query_count": {"type": "int", "description": "Number of DNS queries in flow"},
        "dns_mean_entropy": {"type": "float", "description": "Mean Shannon entropy of queried domain names"},
        "dns_max_entropy": {"type": "float", "description": "Max Shannon entropy across queries"},
        "dns_mean_length": {"type": "float", "description": "Mean domain name character length"},
        "dns_ngram_score": {"type": "float", "description": "Anomalous n-gram score for DGA detection"},
        "dns_tunneling_flag": {"type": "bool", "description": "Flag for suspected DNS tunneling/DGA"},
        "has_tls": {"type": "bool", "description": "True if TLS handshake was detected"},
        "sni_domain": {"type": "str", "description": "Server Name Indication (SNI) extension domain"},
        "ja3_fingerprint": {"type": "str", "description": "Client JA3 MD5 hash fingerprint"},
        "ja3s_fingerprint": {"type": "str", "description": "Server JA3S MD5 hash fingerprint"},
        "tls_version": {"type": "str", "description": "TLS version identifier"},
        "cipher_suites_count": {"type": "int", "description": "Number of offered cipher suites"},
        "src_fanout_dst_ips_1m": {"type": "int", "description": "Unique destination IPs contacted by src_ip in 1m window"},
        "src_fanout_dst_ports_1m": {"type": "int", "description": "Unique destination ports contacted by src_ip in 1m window"},
        "bytes_ratio_fwd_bwd": {"type": "float", "description": "Ratio of forward bytes to backward bytes"},
        "label": {"type": "str", "description": "Ground truth label (benign, ddos, c2_beaconing, etc.)"}
    }
