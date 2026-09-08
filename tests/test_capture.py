from scapy.all import IP, TCP, Ether, wrpcap
from src.capture.packet_sniffer import PassivePacketSniffer
from src.capture.malformed_handler import MalformedHandler
from src.injector.attack_injector import SyntheticAttackInjector

def test_pcap_read_and_passive_sniff(tmp_path):
    pcap_file = str(tmp_path / "test_sample.pcap")
    injector = SyntheticAttackInjector()
    packets = injector.generate_c2_beaconing(count=5)
    wrpcap(pcap_file, packets)

    captured_packets = []
    def callback(pkt):
        captured_packets.append(pkt)

    sniffer = PassivePacketSniffer()
    processed_cnt = sniffer.read_pcap(pcap_file, callback)

    assert processed_cnt == len(packets)
    assert len(captured_packets) == len(packets)
    assert sniffer.total_packets_captured == len(packets)
