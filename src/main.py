import os
import sys

# Ensure root workspace is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import yaml
import time
import logging
import argparse
from typing import Optional

from src.schema.flow_schema import get_schema_metadata
from src.capture.packet_sniffer import PassivePacketSniffer
from src.capture.malformed_handler import MalformedHandler
from src.features.flow_aggregator import FlowAggregator
from src.injector.attack_injector import SyntheticAttackInjector
from src.handoff.feature_emitter import FeatureEmitter

def setup_logging(log_file: str = "pipeline.log", level: str = "INFO"):
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(log_file, mode='a', encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def main():
    parser = argparse.ArgumentParser(description="Passive Traffic & Data Engineering Module (SIH26145 - Person 1)")
    parser.add_argument("--config", default="config/pipeline_config.yaml", help="Path to config YAML")
    parser.add_argument("--pcap", default=None, help="Process offline PCAP file instead of live capture")
    parser.add_argument("--generate-attacks", action="store_true", help="Generate synthetic attack PCAP first")
    parser.add_argument("--output", default=None, help="Output JSON lines file path")
    args = parser.parse_args()

    # Load config
    config = {}
    if os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config = yaml.safe_load(f)

    log_cfg = config.get("logging", {})
    setup_logging(log_cfg.get("log_file", "pipeline.log"), log_cfg.get("level", "INFO"))

    logger = logging.getLogger("TrafficPipeline.Main")
    logger.info("Initializing Passive Traffic Capture & Feature Extraction Pipeline...")

    malformed_handler = MalformedHandler(log_anomalies=log_cfg.get("log_malformed", True))
    sniffer = PassivePacketSniffer(
        malformed_handler=malformed_handler,
        one_way_enforced=config.get("capture", {}).get("one_way_enforced", True)
    )

    flow_cfg = config.get("flow", {})
    aggregator = FlowAggregator(
        inactivity_timeout=flow_cfg.get("inactivity_timeout_sec", 5.0),
        active_timeout=flow_cfg.get("active_timeout_sec", 60.0)
    )

    output_path = args.output or config.get("handoff", {}).get("output_file", "output_flows.jsonl")
    emitter = FeatureEmitter(output_filepath=output_path, stream_to_stdout=False)

    pcap_to_process = args.pcap

    if args.generate_attacks:
        injector = SyntheticAttackInjector()
        gen_pcap = "synthetic_attacks_sample.pcap"
        logger.info("Generating synthetic attack PCAP covering all 6 categories...")
        injector.export_synthetic_pcap(gen_pcap)
        logger.info(f"Synthetic attack PCAP created at '{gen_pcap}'")
        if not pcap_to_process:
            pcap_to_process = gen_pcap

    def packet_callback(packet):
        flushed_flow = aggregator.add_packet(packet)
        if flushed_flow:
            emitter.emit_flow(flushed_flow)

    start_time = time.time()

    if pcap_to_process:
        logger.info(f"Starting PCAP processing mode for: {pcap_to_process}")
        packet_count = sniffer.read_pcap(pcap_to_process, packet_callback)
        flushed = aggregator.flush_all()
        emitter.emit_batch(flushed)
        elapsed = time.time() - start_time
        logger.info(
            f"PCAP processing complete. Packets={packet_count}, "
            f"Flows Emitted={emitter.emitted_count}, Elapsed={elapsed:.3f}s"
        )
    else:
        iface = config.get("capture", {}).get("interface", "eth0")
        logger.info(f"Starting live passive capture on interface: {iface}")
        try:
            sniffer.start_live_capture(interface=iface, callback=packet_callback, timeout=10.0)
        except KeyboardInterrupt:
            logger.info("Stopping live capture on user request.")
        finally:
            flushed = aggregator.flush_all()
            emitter.emit_batch(flushed)

    emitter.close()
    stats = malformed_handler.get_stats()
    logger.info(f"Pipeline Execution Stats: Malformed Packets={stats['total_malformed_packets']}, Total Flows Emitted={emitter.emitted_count}")

if __name__ == "__main__":
    main()
