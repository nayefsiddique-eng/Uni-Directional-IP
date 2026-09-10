import pytest
from src.ml.fusion_engine import EvidenceFusionEngine
from tests.test_ml_detectors import create_mock_flow

def test_evidence_fusion_engine():
    fusion = EvidenceFusionEngine()

    c2_flow = create_mock_flow(periodicity_score=0.90, label="c2_beaconing")
    incident = fusion.evaluate_flow(c2_flow)

    assert incident is not None
    assert incident.threat_category == "c2_beaconing"
    assert incident.confidence >= 0.85
    assert incident.severity in ["CRITICAL", "HIGH"]
    assert "T1071" in incident.mitre_attack_id
    assert len(incident.evidence_points) > 0
    assert incident.suppressed is False
