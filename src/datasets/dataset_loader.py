"""
Public Dataset Normalizer & Loader (FR6).
Normalizes public benchmark datasets (CICIDS2017/2018, CTU-13) into the unified FlowRecord feature schema.
"""

import csv
import os
import hashlib
from typing import List, Dict, Any, Generator
from ..schema.flow_schema import FlowRecord

class DatasetLoader:
    CICIDS_LABEL_MAP = {
        "BENIGN": "benign",
        "DDoS": "ddos",
        "DoS Hulk": "ddos",
        "DoS GoldenEye": "ddos",
        "DoS slowloris": "ddos",
        "DoS Slowhttptest": "ddos",
        "PortScan": "port_scan",
        "Bot": "c2_beaconing",
        "Infiltration": "data_exfiltration",
        "Web Attack – Brute Force": "port_scan",
        "FTP-Patator": "port_scan",
        "SSH-Patator": "port_scan"
    }

    CTU13_LABEL_MAP = {
        "Background": "benign",
        "Normal": "benign",
        "Botnet": "c2_beaconing",
        "C&C": "c2_beaconing"
    }

    @staticmethod
    def _to_float(val: Any, default: float = 0.0) -> float:
        try:
            v = float(val)
            return 0.0 if (v != v or v == float('inf') or v == float('-inf')) else v
        except Exception:
            return default

    @staticmethod
    def _to_int(val: Any, default: int = 0) -> int:
        try:
            return int(float(val))
        except Exception:
            return default

    def load_cicids_csv(self, csv_filepath: str, max_rows: int = 10000) -> List[FlowRecord]:
        """Loads and normalizes CICIDS2017 / CICIDS2018 CSV dataset."""
        if not os.path.exists(csv_filepath):
            raise FileNotFoundError(f"CICIDS dataset file not found: {csv_filepath}")

        records = []
        with open(csv_filepath, mode='r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            # Strip whitespace from headers
            reader.fieldnames = [h.strip() for h in reader.fieldnames] if reader.fieldnames else []

            for idx, row in enumerate(reader):
                if idx >= max_rows:
                    break

                # Extract basic fields
                src_ip = row.get("Source IP", row.get("Src IP", "192.168.1.10"))
                dst_ip = row.get("Destination IP", row.get("Dst IP", "10.0.0.1"))
                src_port = self._to_int(row.get("Source Port", row.get("Src Port", 0)))
                dst_port = self._to_int(row.get("Destination Port", row.get("Dst Port", 0)))
                proto = "TCP" if row.get("Protocol") == "6" else ("UDP" if row.get("Protocol") == "17" else "OTHER")

                flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
                flow_id = hashlib.md5(flow_key.encode()).hexdigest()[:16]

                duration = self._to_float(row.get("Flow Duration", 0)) / 1e6  # Microseconds to sec
                fwd_pkts = self._to_int(row.get("Total Fwd Packets", row.get("Tot Fwd Pkts", 0)))
                bwd_pkts = self._to_int(row.get("Total Backward Packets", row.get("Tot Bwd Pkts", 0)))
                fwd_bytes = self._to_int(row.get("Total Length of Fwd Packets", row.get("TotLen Fwd Pkts", 0)))
                bwd_bytes = self._to_int(row.get("Total Length of Bwd Packets", row.get("TotLen Bwd Pkts", 0)))

                raw_label = row.get("Label", "BENIGN").strip()
                norm_label = self.CICIDS_LABEL_MAP.get(raw_label, "benign")

                rec = FlowRecord(
                    flow_id=flow_id,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto,
                    timestamp_first=1700000000.0 + idx,
                    timestamp_last=1700000000.0 + idx + duration,
                    duration=duration,
                    fwd_packets=fwd_pkts,
                    bwd_packets=bwd_pkts,
                    total_packets=fwd_pkts + bwd_pkts,
                    fwd_bytes=fwd_bytes,
                    bwd_bytes=bwd_bytes,
                    total_bytes=fwd_bytes + bwd_bytes,
                    bytes_per_sec=self._to_float(row.get("Flow Bytes/s", 0)),
                    packets_per_sec=self._to_float(row.get("Flow Packets/s", 0)),
                    pkt_size_min=self._to_int(row.get("Min Packet Length", 0)),
                    pkt_size_max=self._to_int(row.get("Max Packet Length", 0)),
                    pkt_size_mean=self._to_float(row.get("Packet Length Mean", 0)),
                    pkt_size_std=self._to_float(row.get("Packet Length Std", 0)),
                    iat_min=self._to_float(row.get("Fwd IAT Min", row.get("Flow IAT Min", 0))) / 1e6,
                    iat_max=self._to_float(row.get("Fwd IAT Max", row.get("Flow IAT Max", 0))) / 1e6,
                    iat_mean=self._to_float(row.get("Fwd IAT Mean", row.get("Flow IAT Mean", 0))) / 1e6,
                    iat_std=self._to_float(row.get("Fwd IAT Std", row.get("Flow IAT Std", 0))) / 1e6,
                    periodicity_score=0.5 if norm_label == "c2_beaconing" else 0.0,
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
                    src_fanout_dst_ips_1m=10 if norm_label == "port_scan" else 1,
                    src_fanout_dst_ports_1m=50 if norm_label == "port_scan" else 1,
                    bytes_ratio_fwd_bwd=round(fwd_bytes / max(1, bwd_bytes), 4),
                    label=norm_label
                )
                records.append(rec)
        return records

    def load_ctu13_netflow(self, netflow_filepath: str, max_rows: int = 10000) -> List[FlowRecord]:
        """Loads and normalizes CTU-13 NetFlow CSV/Binetflow format dataset."""
        if not os.path.exists(netflow_filepath):
            raise FileNotFoundError(f"CTU-13 file not found: {netflow_filepath}")

        records = []
        with open(netflow_filepath, mode='r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            reader.fieldnames = [h.strip() for h in reader.fieldnames] if reader.fieldnames else []

            for idx, row in enumerate(reader):
                if idx >= max_rows:
                    break

                src_ip = row.get("SrcAddr", "192.168.1.10")
                dst_ip = row.get("DstAddr", "10.0.0.1")
                src_port = self._to_int(row.get("Sport", 0))
                dst_port = self._to_int(row.get("Dport", 0))
                proto = row.get("Proto", "TCP").upper()

                flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
                flow_id = hashlib.md5(flow_key.encode()).hexdigest()[:16]

                duration = self._to_float(row.get("Dur", 0))
                tot_pkts = self._to_int(row.get("TotPkts", 1))
                tot_bytes = self._to_int(row.get("TotBytes", 64))

                raw_label = row.get("Label", "Normal")
                norm_label = "c2_beaconing" if "Botnet" in raw_label else "benign"

                rec = FlowRecord(
                    flow_id=flow_id,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto,
                    timestamp_first=1700000000.0 + idx,
                    timestamp_last=1700000000.0 + idx + duration,
                    duration=duration,
                    fwd_packets=tot_pkts,
                    bwd_packets=0,
                    total_packets=tot_pkts,
                    fwd_bytes=tot_bytes,
                    bwd_bytes=0,
                    total_bytes=tot_bytes,
                    bytes_per_sec=self._to_float(tot_bytes / max(0.001, duration)),
                    packets_per_sec=self._to_float(tot_pkts / max(0.001, duration)),
                    pkt_size_min=int(tot_bytes / tot_pkts),
                    pkt_size_max=int(tot_bytes / tot_pkts),
                    pkt_size_mean=float(tot_bytes / tot_pkts),
                    pkt_size_std=0.0,
                    iat_min=0.0,
                    iat_max=0.0,
                    iat_mean=self._to_float(duration / max(1, tot_pkts)),
                    iat_std=0.0,
                    periodicity_score=0.8 if norm_label == "c2_beaconing" else 0.0,
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
                    bytes_ratio_fwd_bwd=1.0,
                    label=norm_label
                )
                records.append(rec)
        return records
