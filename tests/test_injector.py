import pytest
from src.injector.attack_injector import SyntheticAttackInjector

def test_synthetic_injector_all_categories():
    injector = SyntheticAttackInjector()
    attacks = injector.generate_all_attack_categories()

    # Check all 6 FR5 required attack categories
    expected_categories = [
        "ddos", "c2_beaconing", "dga_dns_tunneling",
        "malware_tls", "port_scan", "data_exfiltration"
    ]

    for cat in expected_categories:
        assert cat in attacks
        assert len(attacks[cat]) > 0
