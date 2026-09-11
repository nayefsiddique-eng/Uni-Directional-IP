"""
Unsupervised Anomaly Detector (FR3).
Uses Isolation Forest anomaly scoring for zero-day & unknown traffic pattern detection.
"""

import numpy as np
from typing import Dict, Any
from sklearn.ensemble import IsolationForest
from ..schema.flow_schema import FlowRecord

class UnsupervisedDetector:
    def __init__(self):
        self.model_version = "v1.0-IsolationForest"
        self.clf = IsolationForest(n_estimators=50, contamination=0.05, random_state=42)
        self._is_fitted = False
        self._init_baseline()

    def _init_baseline(self):
        """Fits baseline model on normal traffic feature distributions."""
        np.random.seed(42)
        # Synthetic benign baseline features: [duration, pkt_size_mean, iat_mean, bytes_per_sec]
        normal_data = np.random.normal(loc=[1.5, 200, 0.1, 1000], scale=[0.5, 50, 0.05, 300], size=(200, 4))
        self.clf.fit(normal_data)
        self._is_fitted = True

    def predict_anomaly(self, flow: FlowRecord) -> Dict[str, Any]:
        """Calculates anomaly score (0.0 to 1.0, where >0.65 indicates anomaly)."""
        feat_vector = np.array([[flow.duration, flow.pkt_size_mean, flow.iat_mean, flow.bytes_per_sec]])
        
        # Raw decision function (lower means more anomalous)
        raw_score = float(self.clf.decision_function(feat_vector)[0])
        # Convert raw decision score to 0..1 range (higher = more anomalous)
        anomaly_score = round(max(0.0, min(1.0, 0.5 - raw_score)), 4)
        is_anomaly = anomaly_score > 0.60

        return {
            "unsupervised_anomaly_score": anomaly_score,
            "is_anomaly": is_anomaly,
            "raw_decision_score": round(raw_score, 4)
        }
