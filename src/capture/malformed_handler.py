"""
Malformed Packet Handler & Anomaly Logger for Passive Capture Pipeline.
Ensures zero pipeline crashes when handling corrupted/truncated packets (FR7).
"""

import logging
import traceback
import time
from typing import Dict, Any, Optional

logger = logging.getLogger("TrafficPipeline.MalformedHandler")

class MalformedPacketError(Exception):
    """Custom exception for corrupted network packets."""
    pass

class MalformedHandler:
    def __init__(self, log_anomalies: bool = True):
        self.log_anomalies = log_anomalies
        self.malformed_count = 0
        self.anomaly_log = []

    def handle_exception(self, packet_raw: bytes, exception: Exception, context: str = "Packet Processing") -> None:
        """Logs malformed/corrupted packet details without stopping execution."""
        self.malformed_count += 1
        timestamp = time.time()
        
        raw_hex_snippet = packet_raw[:64].hex() if packet_raw else "EMPTY"
        error_msg = str(exception)
        
        record = {
            "timestamp": timestamp,
            "context": context,
            "error": error_msg,
            "raw_len": len(packet_raw) if packet_raw else 0,
            "hex_snippet": raw_hex_snippet,
            "traceback": traceback.format_exc()
        }
        self.anomaly_log.append(record)

        if self.log_anomalies:
            logger.warning(
                f"[FR7 ANOMALY] Malformed packet detected in '{context}'. "
                f"Count={self.malformed_count}, Error={error_msg}, Snippet={raw_hex_snippet[:30]}..."
            )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_malformed_packets": self.malformed_count,
            "recent_anomalies": self.anomaly_log[-10:]
        }
