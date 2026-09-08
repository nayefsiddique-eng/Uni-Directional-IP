"""
Throughput and Latency Benchmark Test Suite.
Verifies FR3 performance requirements: Latency < 100ms per flow, high throughput streaming.
"""

import time
import os
import sys
import numpy as np

# Ensure root workspace is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.injector.attack_injector import SyntheticAttackInjector
from src.features.flow_aggregator import FlowAggregator
from src.capture.packet_sniffer import PassivePacketSniffer
from src.handoff.feature_emitter import FeatureEmitter

def run_benchmark():
    print("==========================================================")
    print("   TRAFFIC PIPELINE BENCHMARK (SIH26145 - PERSON 1)       ")
    print("==========================================================")

    injector = SyntheticAttackInjector()
    print("[1/3] Synthesizing benchmark packet stream (all 6 attack categories)...")
    attacks = injector.generate_all_attack_categories()
    
    total_packets = sum(len(pkts) for pkts in attacks.values())
    print(f"      Total Synthetic Packets Generated: {total_packets}")

    aggregator = FlowAggregator()
    emitter = FeatureEmitter()

    flow_latencies = []
    start_time = time.time()
    flows_emitted = 0

    print("[2/3] Executing capture, flow reconstruction, & feature extraction...")

    for attack_type, pkts in attacks.items():
        for pkt in pkts:
            t0 = time.perf_counter()
            flow = aggregator.add_packet(pkt, label=attack_type)
            if flow:
                t1 = time.perf_counter()
                latency_ms = (t1 - t0) * 1000.0
                flow_latencies.append(latency_ms)
                emitter.emit_flow(flow)
                flows_emitted += 1

    # Flush remaining active flows
    t0 = time.perf_counter()
    flushed = aggregator.flush_all()
    t1 = time.perf_counter()
    flush_latency_ms = (t1 - t0) * 1000.0

    for flow in flushed:
        flow_latencies.append(flush_latency_ms / max(1, len(flushed)))
        emitter.emit_flow(flow)
        flows_emitted += 1

    total_elapsed = time.time() - start_time
    pkts_per_sec = total_packets / max(0.001, total_elapsed)
    flows_per_sec = flows_emitted / max(0.001, total_elapsed)

    mean_latency = float(np.mean(flow_latencies)) if flow_latencies else 0.0
    p95_latency = float(np.percentile(flow_latencies, 95)) if flow_latencies else 0.0
    max_latency = float(np.max(flow_latencies)) if flow_latencies else 0.0

    print("\n==========================================================")
    print("                  BENCHMARK RESULTS                       ")
    print("==========================================================")
    print(f" Total Processing Time : {total_elapsed:.4f} seconds")
    print(f" Total Flows Processed : {flows_emitted}")
    print(f" Packet Throughput     : {pkts_per_sec:.2f} packets/sec")
    print(f" Flow Throughput       : {flows_per_sec:.2f} flows/sec")
    print(f" Mean Latency / Flow   : {mean_latency:.4f} ms")
    print(f" P95 Latency / Flow    : {p95_latency:.4f} ms")
    print(f" Max Latency / Flow    : {max_latency:.4f} ms")
    print("----------------------------------------------------------")

    target_latency_ms = 100.0
    if mean_latency < target_latency_ms:
        print(f" SUCCESS: Mean latency ({mean_latency:.2f}ms) is well under target (<{target_latency_ms}ms)!")
    else:
        print(f" WARNING: Mean latency exceeded target ({target_latency_ms}ms)")

if __name__ == "__main__":
    run_benchmark()
