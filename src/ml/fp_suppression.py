"""
False-Positive Suppression Engine (FR6: Person 2).
Tracks low-confidence signals, white-listed baselines, and recurring benign activity to prevent SOC analyst alert fatigue.
"""

from typing import Dict, Any, List, Optional
from ..schema.flow_schema import FlowRecord

class FPSuppressionTracker:
    def __init__(self, confidence_threshold: float = 0.50):
        self.confidence_threshold = confidence_threshold
        self.suppressed_count = 0
        self.whitelist_ips = {"127.0.0.1", "10.0.0.1"}

    def should_suppress(self, flow: FlowRecord, top_category: str, raw_confidence: float) -> tuple:
        """
        Determines whether an alert should be suppressed.
        Returns (is_suppressed, reason)
        """
        if raw_confidence < self.confidence_threshold:
            self.suppressed_count += 1
            return True, f"Confidence score ({raw_confidence:.2f}) below operational threshold ({self.confidence_threshold:.2f})."

        if flow.src_ip in self.whitelist_ips and top_category == "benign":
            self.suppressed_count += 1
            return True, f"Source IP {flow.src_ip} is in verified baseline whitelist."

        return False, ""

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_suppressed_alerts": self.suppressed_count,
            "confidence_threshold": self.confidence_threshold
        }
