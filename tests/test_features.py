import pytest
from src.features.dns_analyzer import DNSAnalyzer
from src.features.tls_analyzer import TLSAnalyzer
from src.features.flow_aggregator import FlowAggregator
from src.injector.attack_injector import SyntheticAttackInjector

def test_dns_analyzer_entropy_and_tunneling():
    analyzer = DNSAnalyzer()
    
    # Benign domain
    benign_res = analyzer.analyze_queries(["google.com", "api.github.com"])
    assert benign_res["dns_mean_entropy"] < 3.8
    assert not benign_res["dns_tunneling_flag"]

    # DGA High entropy subdomains
    dga_subdomains = [
        "x7a9k2m1p4q8z9w0v3.malicious-tunneling-service.net",
        "89f2a4c1e6b8d0e2f4a6.c2-data-exfil-node.org"
    ]
    dga_res = analyzer.analyze_queries(dga_subdomains)
    assert dga_res["dns_max_entropy"] > 3.5
    assert dga_res["dns_tunneling_flag"] is True

def test_flow_aggregation_and_features():
    injector = SyntheticAttackInjector()
    packets = injector.generate_c2_beaconing(count=10)
    
    aggregator = FlowAggregator()
    emitted_flows = []
    
    for pkt in packets:
        res = aggregator.add_packet(pkt, label="c2_beaconing")
        if res:
            emitted_flows.append(res)
            
    flushed = aggregator.flush_all()
    emitted_flows.extend(flushed)

    assert len(emitted_flows) > 0
    flow = emitted_flows[0]
    assert flow.total_packets >= 10
    assert flow.label == "c2_beaconing"
    assert flow.periodicity_score > 0.3  # Beaconing packet sequence should score periodic
