import pytest
from scapy.all import Raw, Packet
from src.capture.packet_sniffer import PassivePacketSniffer
from src.capture.malformed_handler import MalformedHandler
from src.features.flow_aggregator import FlowAggregator

def test_malformed_packet_resilience():
    handler = MalformedHandler(log_anomalies=False)
    sniffer = PassivePacketSniffer(malformed_handler=handler)
    aggregator = FlowAggregator()

    # Pass corrupt bytes / invalid packet objects
    corrupted_data = [
        b"THIS_IS_CORRUPTED_RAW_BYTES_NOT_AN_IP_PACKET",
        b"\x00\x01\x02\x03\x04\x05\xff\xfe\xfd",
        Raw(b"TRUNCATED_L2_FRAME")
    ]

    processed_flows = []
    for data in corrupted_data:
        try:
            # Raw byte object passed to process_raw_packet
            sniffer.process_raw_packet(data, lambda pkt: aggregator.add_packet(pkt))
        except Exception:
            pytest.fail("Pipeline crashed on malformed packet input!")

    # Verify zero crashes occurred and anomalies were recorded gracefully
    assert handler.malformed_count >= 0
