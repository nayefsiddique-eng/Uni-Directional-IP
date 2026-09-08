# Traffic & Data Engineering Module (SIH26145 - Person 1)

## Overview
This module provides a **Passive Traffic Capture & Feature Extraction Pipeline**, **Synthetic Attack Injector**, and **Public Dataset Integrator** operating strictly downstream of a data diode (100% one-way passive inspection, zero outbound packet transmission).

## Features & Capabilities
1. **Passive Traffic Capture (FR1 & FR2):**
   - Supports both offline PCAP replay mode and live passive network interface sniffing.
   - Reconstructs bi-directional 5-tuple flows (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`).
2. **Feature Extraction Engine (FR3):**
   - Packet size distribution (min, max, mean, std).
   - Inter-arrival timing & periodicity scoring.
   - Unencrypted TLS handshake parsing, Server Name Indication (SNI), and JA3 / JA3S MD5 fingerprinting.
   - DNS query analysis: Shannon entropy, domain length, character n-gram irregularity scoring, and DNS tunneling detection flags.
   - Sliding window connection fan-out metrics (unique destination IPs and ports per source IP in 1-minute window).
3. **Synthetic Attack Injector (FR5):**
   - Generates labeled synthetic traffic covering all 6 attack categories:
     - **DDoS** (Volumetric TCP SYN flood)
     - **C2 Beaconing** (Periodic connection pulses)
     - **DGA / DNS Tunneling** (High-entropy subdomains & TXT queries)
     - **Encrypted Malware Traffic** (Non-standard TLS fingerprints)
     - **Port Scanning** (High fan-out across destination ports)
     - **Data Exfiltration** (Asymmetric large outbound byte transfers)
4. **Public Dataset Integration (FR6):**
   - Normalizer for CICIDS2017/2018 CSVs and CTU-13 NetFlow datasets into the standardized schema.
5. **Fault Tolerance & Malformed Packet Handling (FR7):**
   - Zero-crash guarantee when encountering corrupted/truncated frame captures.
   - Logs anomaly metadata for audit.

---

## Installation & Setup

```bash
pip install -r requirements.txt
```

---

## Usage

### 1. Run Pipeline with Synthetic Attack PCAP Generation
```bash
python src/main.py --generate-attacks --output output_flows.jsonl
```

### 2. Process an Existing PCAP File
```bash
python src/main.py --pcap path/to/sample.pcap --output output_flows.jsonl
```

### 3. Run Benchmark Suite
```bash
python benchmarks/benchmark_pipeline.py
```

### 4. Run Automated Unit Tests
```bash
pytest tests/
```

### 5. Docker Build & Run
```bash
docker build -t traffic-pipeline:v1 .
docker run --rm -v $(pwd):/app traffic-pipeline:v1 --generate-attacks
```

---

## Schema Contract (Handoff to Person 2 - ML Module)
Each flow emitted is serialized as JSON matching the `FlowRecord` dataclass in `src/schema/flow_schema.py`.
