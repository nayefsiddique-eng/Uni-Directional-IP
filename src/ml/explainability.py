"""
Rule-Based Feature Attribution Explainer (FR5).
Computes feature attribution weights and natural-language evidence summaries per incident.
"""

from typing import Dict, Any, List
from ..schema.flow_schema import FlowRecord

class FeatureAttributionExplainer:
    def explain_flow(self, flow: FlowRecord, attack_type: str, confidence: float) -> Dict[str, Any]:
        """Calculates rule-based feature attributions and natural language evidence summary."""
        attributions = {}
        evidence_lines = []

        if attack_type == "ddos":
            attributions = {
                "packets_per_sec": round(min(0.45, flow.packets_per_sec / 300.0), 3),
                "total_packets": round(min(0.35, flow.total_packets / 400.0), 3),
                "pkt_size_mean": 0.20
            }
            evidence_lines.append(f"Extremely high packet rate ({flow.packets_per_sec:.1f} pkts/sec).")
            evidence_lines.append(f"Volumetric surge totaling {flow.total_packets} packets within {flow.duration:.2f}s.")

        elif attack_type == "port_scan":
            attributions = {
                "src_fanout_dst_ports_1m": round(min(0.60, flow.src_fanout_dst_ports_1m / 50.0), 3),
                "src_fanout_dst_ips_1m": round(min(0.25, flow.src_fanout_dst_ips_1m / 20.0), 3),
                "duration": 0.15
            }
            evidence_lines.append(f"High destination port fan-out ({flow.src_fanout_dst_ports_1m} unique ports probed).")

        elif attack_type == "c2_beaconing":
            attributions = {
                "periodicity_score": round(flow.periodicity_score * 0.55, 3),
                "iat_std": round(max(0.0, 0.30 - flow.iat_std), 3),
                "total_packets": 0.15
            }
            evidence_lines.append(f"Highly regular inter-arrival timing (Periodicity Index = {flow.periodicity_score:.2f}).")
            evidence_lines.append(f"Fixed-interval C2 beaconing pulses to destination IP {flow.dst_ip}.")

        elif attack_type == "dga_dns_tunneling":
            attributions = {
                "dns_mean_entropy": round(min(0.50, flow.dns_mean_entropy / 4.5), 3),
                "dns_ngram_score": round(flow.dns_ngram_score * 0.30, 3),
                "dns_mean_length": round(min(0.20, flow.dns_mean_length / 50.0), 3)
            }
            evidence_lines.append(f"High Shannon entropy domain names (Max Entropy = {flow.dns_max_entropy:.2f} bits/symbol).")
            evidence_lines.append(f"Anomalous character n-gram distribution typical of DGA subdomains.")

        elif attack_type == "malware_tls":
            attributions = {
                "cipher_suites_count": 0.45,
                "has_tls": 0.35,
                "ja3_fingerprint": 0.20
            }
            evidence_lines.append("Anomalous TLS ClientHello payload with restricted cipher suite count.")

        elif attack_type == "data_exfiltration":
            attributions = {
                "bytes_ratio_fwd_bwd": round(min(0.50, flow.bytes_ratio_fwd_bwd / 10.0), 3),
                "total_bytes": round(min(0.35, flow.total_bytes / 100000.0), 3),
                "fwd_bytes": 0.15
            }
            evidence_lines.append(f"Large asymmetric forward data transfer ({flow.fwd_bytes} outbound vs {flow.bwd_bytes} inbound bytes).")
        else:
            attributions = {"unsupervised_anomaly_score": 0.80, "pkt_size_std": 0.20}
            evidence_lines.append("Anomalous baseline metric distribution detected by Isolation Forest.")

        return {
            "feature_attributions": attributions,
            "evidence_summary": " ".join(evidence_lines),
            "evidence_points": evidence_lines
        }
