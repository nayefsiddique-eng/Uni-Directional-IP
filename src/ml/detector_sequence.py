"""
Sequence & Signal Detector (FR3).
Analyzes C2 Beaconing periodicity, DNS Tunneling/DGA entropy, and TLS Handshake fingerprints.
Detections are computed strictly from extracted flow features — zero label lookup.
"""

from typing import Dict, Any
from ..schema.flow_schema import FlowRecord

class SequenceDetector:
    def __init__(self):
        self.model_version = "v1.1-SequenceSignal"

    def analyze_sequence(self, flow: FlowRecord) -> Dict[str, float]:
        """Returns category probabilities for C2 Beaconing, DGA/DNS Tunneling, and Malware TLS."""
        scores = {
            "c2_beaconing": 0.0,
            "dga_dns_tunneling": 0.0,
            "malware_tls": 0.0
        }

        # 1. C2 Beaconing (High periodicity score & steady inter-arrival times)
        if flow.periodicity_score > 0.35 and flow.total_packets >= 3:
            scores["c2_beaconing"] = round(min(1.0, flow.periodicity_score * 1.2), 4)

        # 2. DGA / DNS Tunneling (High domain Shannon entropy or n-gram irregularity)
        if flow.dns_tunneling_flag or flow.dns_mean_entropy > 3.5 or flow.dns_ngram_score > 0.4:
            dga_score = min(1.0, (flow.dns_mean_entropy / 4.5) + (flow.dns_ngram_score * 0.5))
            scores["dga_dns_tunneling"] = round(dga_score, 4)

        # 3. Encrypted Malware TLS (Anomalous JA3 fingerprint, non-standard cipher count)
        if flow.has_tls and (flow.cipher_suites_count > 0 and flow.cipher_suites_count <= 4):
            scores["malware_tls"] = 0.85

        return scores
