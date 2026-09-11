"""
Supervised Threat Classifier (FR3: Person 2).
Provides rule-based feature heuristic classification for DDoS, Port Scanning, and Data Exfiltration.
Detections are computed strictly from extracted flow features — zero label lookup.
"""

from typing import Dict, Any
from ..schema.flow_schema import FlowRecord

class SupervisedDetector:
    def __init__(self):
        self.model_version = "v1.2.0-HeuristicEngine"

    def predict_flow(self, flow: FlowRecord) -> Dict[str, float]:
        """
        Evaluates flow features and outputs threat probabilities per category.
        Returns dict mapping category name -> score (0.0 to 1.0).
        """
        scores = {
            "ddos": 0.0,
            "port_scan": 0.0,
            "data_exfiltration": 0.0
        }

        # 1. DDoS Detection Logic (Volumetric packet rate & high total packet count within short window)
        if flow.packets_per_sec > 50.0 or (flow.total_packets >= 40 and flow.duration <= 5.0):
            d_score = min(1.0, (flow.packets_per_sec / 150.0) + (flow.total_packets / 250.0))
            scores["ddos"] = round(d_score, 4)

        # 2. Port Scanning Detection Logic (High unique destination ports fan-out)
        if flow.src_fanout_dst_ports_1m >= 5:
            ps_score = min(1.0, flow.src_fanout_dst_ports_1m / 25.0)
            scores["port_scan"] = round(ps_score, 4)

        # 3. Data Exfiltration Detection Logic (High forward-to-backward byte ratio & large outbound bytes)
        if flow.total_bytes > 5000 and flow.bytes_ratio_fwd_bwd > 2.0:
            ex_score = min(1.0, (flow.bytes_ratio_fwd_bwd / 5.0) * (flow.total_bytes / 25000.0))
            scores["data_exfiltration"] = round(ex_score, 4)

        return scores
