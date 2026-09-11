"""
Evidence Fusion & Incident Correlation Engine (FR4: Person 2).
Fuses multi-signal detection probabilities into unified, scored, and explainable Incidents.
"""

import time
import hashlib
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional
from ..schema.flow_schema import FlowRecord
from .detector_supervised import SupervisedDetector
from .detector_unsupervised import UnsupervisedDetector
from .detector_sequence import SequenceDetector
from .explainability import FeatureAttributionExplainer
from .fp_suppression import FPSuppressionTracker

@dataclass
class Incident:
    incident_id: str
    timestamp: float
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    threat_category: str
    confidence: float
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    mitre_attack_id: str
    evidence_summary: str
    evidence_points: List[str]
    feature_attributions: Dict[str, float]
    suppressed: bool
    suppression_reason: str
    model_version: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class EvidenceFusionEngine:
    MITRE_MAPPING = {
        "ddos": "T1498 - Network Denial of Service",
        "port_scan": "T1046 - Network Service Discovery",
        "c2_beaconing": "T1071 - Application Layer Protocol (C2)",
        "dga_dns_tunneling": "T1568 - Dynamic Resolution (DGA)",
        "malware_tls": "T1573 - Encrypted Channel",
        "data_exfiltration": "T1048 - Exfiltration Over Alternative Protocol",
        "anomaly": "T1036 - Masquerading / Unknown Anomaly"
    }

    def __init__(self):
        self.supervised = SupervisedDetector()
        self.unsupervised = UnsupervisedDetector()
        self.sequence = SequenceDetector()
        self.explainer = FeatureAttributionExplainer()
        self.suppressor = FPSuppressionTracker()
        self.incidents_generated = 0

    def evaluate_flow(self, flow: FlowRecord) -> Optional[Incident]:
        """Fuses all signals for a single flow and creates an Incident if threat score > threshold."""
        sup_scores = self.supervised.predict_flow(flow)
        seq_scores = self.sequence.analyze_sequence(flow)
        unsup_res = self.unsupervised.predict_anomaly(flow)

        # Merge category probabilities across detectors
        all_categories = set(sup_scores.keys()).union(seq_scores.keys())
        merged_scores = {}
        for cat in all_categories:
            score1 = sup_scores.get(cat, 0.0)
            score2 = seq_scores.get(cat, 0.0)
            merged_scores[cat] = round(max(score1, score2), 4)

        top_category, top_confidence = max(merged_scores.items(), key=lambda x: x[1])

        # If top category is 0 but unsupervised is anomalous
        if top_confidence < 0.40 and unsup_res["is_anomaly"]:
            top_category = "anomaly"
            top_confidence = unsup_res["unsupervised_anomaly_score"]

        # If benign / low score
        if top_confidence < 0.30:
            return None

        # Check suppression
        suppressed, reason = self.suppressor.should_suppress(flow, top_category, top_confidence)

        # Determine Severity
        if top_confidence >= 0.85:
            severity = "CRITICAL"
        elif top_confidence >= 0.70:
            severity = "HIGH"
        elif top_confidence >= 0.50:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Generate feature attribution explanation
        explanation = self.explainer.explain_flow(flow, top_category, top_confidence)
        mitre_id = self.MITRE_MAPPING.get(top_category, "T1036 - Unknown Anomaly")

        self.incidents_generated += 1
        incident_id = f"INC-{hashlib.md5(f'{flow.flow_id}_{time.time()}'.encode()).hexdigest()[:10].upper()}"

        return Incident(
            incident_id=incident_id,
            timestamp=flow.timestamp_last,
            flow_id=flow.flow_id,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            threat_category=top_category,
            confidence=top_confidence,
            severity=severity,
            mitre_attack_id=mitre_id,
            evidence_summary=explanation["evidence_summary"],
            evidence_points=explanation["evidence_points"],
            feature_attributions=explanation["feature_attributions"],
            suppressed=suppressed,
            suppression_reason=reason,
            model_version=f"{self.supervised.model_version}+{self.sequence.model_version}"
        )
