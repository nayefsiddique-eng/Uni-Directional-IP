import pytest
from src.schema.flow_schema import FlowRecord
from src.ml.detector_supervised import SupervisedDetector
from src.ml.detector_unsupervised import UnsupervisedDetector
from src.ml.detector_sequence import SequenceDetector

def create_mock_flow(label="benign", **kwargs):
    defaults = dict(
        flow_id="test_flow_123",
        src_ip="192.168.1.10",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=80,
        protocol="TCP",
        timestamp_first=1000.0,
        timestamp_last=1002.0,
        duration=2.0,
        fwd_packets=10,
        bwd_packets=5,
        total_packets=15,
        fwd_bytes=1000,
        bwd_bytes=500,
        total_bytes=1500,
        bytes_per_sec=750.0,
        packets_per_sec=7.5,
        pkt_size_min=60,
        pkt_size_max=300,
        pkt_size_mean=100.0,
        pkt_size_std=20.0,
        iat_min=0.01,
        iat_max=0.5,
        iat_mean=0.1,
        iat_std=0.05,
        periodicity_score=0.1,
        dns_query_count=0,
        dns_mean_entropy=0.0,
        dns_max_entropy=0.0,
        dns_mean_length=0.0,
        dns_ngram_score=0.0,
        dns_tunneling_flag=False,
        has_tls=False,
        sni_domain="",
        ja3_fingerprint="",
        ja3s_fingerprint="",
        tls_version="",
        cipher_suites_count=0,
        src_fanout_dst_ips_1m=1,
        src_fanout_dst_ports_1m=1,
        bytes_ratio_fwd_bwd=2.0,
        label=label
    )
    defaults.update(kwargs)
    return FlowRecord(**defaults)

def test_supervised_detector_ddos_and_portscan():
    detector = SupervisedDetector()
    
    ddos_flow = create_mock_flow(packets_per_sec=250.0, total_packets=300, label="ddos")
    scores = detector.predict_flow(ddos_flow)
    assert scores["ddos"] >= 0.90

    scan_flow = create_mock_flow(src_fanout_dst_ports_1m=45, label="port_scan")
    scan_scores = detector.predict_flow(scan_flow)
    assert scan_scores["port_scan"] >= 0.90

def test_sequence_detector_c2_and_dns():
    detector = SequenceDetector()

    c2_flow = create_mock_flow(periodicity_score=0.85, label="c2_beaconing")
    c2_scores = detector.analyze_sequence(c2_flow)
    assert c2_scores["c2_beaconing"] >= 0.90

    dns_flow = create_mock_flow(dns_tunneling_flag=True, dns_mean_entropy=4.2, label="dga_dns_tunneling")
    dns_scores = detector.analyze_sequence(dns_flow)
    assert dns_scores["dga_dns_tunneling"] >= 0.90

def test_unsupervised_detector():
    detector = UnsupervisedDetector()
    normal_flow = create_mock_flow()
    res = detector.predict_anomaly(normal_flow)
    assert "unsupervised_anomaly_score" in res
