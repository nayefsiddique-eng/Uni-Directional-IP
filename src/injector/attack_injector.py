"""
Synthetic Attack Traffic Injector Engine (FR5).
Generates labeled packet streams and PCAPs for all 6 required attack categories:
1. DDoS (Volumetric flood)
2. C2 Beaconing (Periodic connections)
3. DGA / DNS Tunneling (High entropy subdomains)
4. Encrypted Malware-like Traffic (Anomalous TLS fingerprint/timing)
5. Port Scanning (High fan-out across ports)
6. Data Exfiltration (Large anomalous outbound payload transfer)
"""

import time
import random
import string
import hashlib
from typing import List, Tuple, Dict, Any, Optional
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, Packet, wrpcap

class SyntheticAttackInjector:
    def __init__(self, src_subnet: str = "192.168.1", dst_subnet: str = "10.0.0"):
        self.src_subnet = src_subnet
        self.dst_subnet = dst_subnet

    @staticmethod
    def _random_domain(length: int = 16, entropy: str = "high") -> str:
        if entropy == "high":
            # Hex/random alphanumeric string
            chars = string.ascii_lowercase + string.digits
            sub = ''.join(random.choice(chars) for _ in range(length))
            return f"{sub}.malicious-c2-test.net"
        else:
            words = ["login", "api", "update", "auth", "portal", "cdn", "static"]
            return f"{random.choice(words)}.legit-domain.com"

    def generate_ddos_flood(self, count: int = 200, target_ip: str = "10.0.0.50") -> List[Packet]:
        """Generates high-volume TCP SYN flood targeting single IP (FR5: DDoS)."""
        packets = []
        base_time = time.time()
        for i in range(count):
            src_ip = f"{self.src_subnet}.{random.randint(2, 250)}"
            sport = random.randint(1024, 65535)
            pkt = Ether()/IP(src=src_ip, dst=target_ip)/TCP(sport=sport, dport=80, flags="S")/Raw(b"X" * random.randint(10, 60))
            pkt.time = base_time + (i * 0.001)  # Extremely high rate
            packets.append(pkt)
        return packets

    def generate_c2_beaconing(self, count: int = 30, interval: float = 0.5, c2_ip: str = "198.51.100.44") -> List[Packet]:
        """Generates highly periodic beaconing connections to C2 server (FR5: C2 Beaconing)."""
        packets = []
        base_time = time.time()
        src_ip = f"{self.src_subnet}.105"
        sport = 49152
        
        for i in range(count):
            t_curr = base_time + (i * interval) + random.uniform(-0.01, 0.01)  # Strict periodicity with tiny jitter
            # Forward SYN
            syn = Ether()/IP(src=src_ip, dst=c2_ip)/TCP(sport=sport, dport=443, flags="S")
            syn.time = t_curr
            # Backward SYN-ACK
            synack = Ether()/IP(src=c2_ip, dst=src_ip)/TCP(sport=443, dport=sport, flags="SA")
            synack.time = t_curr + 0.005
            # Forward Data / Heartbeat
            data = Ether()/IP(src=src_ip, dst=c2_ip)/TCP(sport=sport, dport=443, flags="PA")/Raw(b"\x16\x03\x01\x00\x20HEARTBEAT_BEACON_DATA_PING")
            data.time = t_curr + 0.010
            
            packets.extend([syn, synack, data])
        return packets

    def generate_dga_dns_tunneling(self, count: int = 25, dns_server: str = "10.0.0.1") -> List[Packet]:
        """Generates DNS queries containing high-entropy DGA subdomains (FR5: DGA/DNS Tunneling)."""
        packets = []
        base_time = time.time()
        src_ip = f"{self.src_subnet}.120"
        
        for i in range(count):
            t_curr = base_time + (i * 0.05)
            sport = random.randint(30000, 60000)
            dga_domain = self._random_domain(length=random.randint(24, 38), entropy="high")
            
            # DNS Query (Forward)
            query = Ether()/IP(src=src_ip, dst=dns_server)/UDP(sport=sport, dport=53)/DNS(rd=1, qd=DNSQR(qname=dga_domain, qtype="TXT"))
            query.time = t_curr
            packets.append(query)
        return packets

    def generate_malware_tls(self, count: int = 15, target_ip: str = "203.0.113.88") -> List[Packet]:
        """Generates TLS handshake with custom/anomalous JA3 fingerprint & payload pattern (FR5: Encrypted Malware)."""
        packets = []
        base_time = time.time()
        src_ip = f"{self.src_subnet}.140"
        sport = 55432
        
        # Synthetic TLS ClientHello payload (handshake type 1) with non-standard ciphers
        tls_client_hello_raw = (
            b"\x16\x03\x01\x00\x45"  # TLS Record Header (Handshake, TLS 1.0, len=69)
            b"\x01\x00\x00\x41"      # Handshake: ClientHello
            b"\x03\x03"              # Version TLS 1.2
            + b"\xAA" * 32           # Random bytes
            + b"\x00"                # Session ID len
            + b"\x00\x08\xc0\x2b\xc0\x2f\x00\x9e\x00\x9f" # 4 Cipher suites
            + b"\x01\x00"            # Compression
            + b"\x00\x10\x00\x00\x00\x0d\x78\x37\x61\x39\x6b\x32\x6d\x31\x2e\x6e\x65\x74" # SNI: x7a9k2m1.net
        )
        
        for i in range(count):
            t_curr = base_time + (i * 0.1)
            pkt = Ether()/IP(src=src_ip, dst=target_ip)/TCP(sport=sport, dport=8443, flags="PA")/Raw(tls_client_hello_raw)
            pkt.time = t_curr
            packets.append(pkt)
        return packets

    def generate_port_scan(self, target_ip: str = "10.0.0.10", port_range: Tuple[int, int] = (20, 150)) -> List[Packet]:
        """Generates single-source port scan across hundreds of ports (FR5: Port Scanning)."""
        packets = []
        base_time = time.time()
        src_ip = f"{self.src_subnet}.222"
        
        for idx, dport in enumerate(range(port_range[0], port_range[1])):
            t_curr = base_time + (idx * 0.002)
            pkt = Ether()/IP(src=src_ip, dst=target_ip)/TCP(sport=51234, dport=dport, flags="S")
            pkt.time = t_curr
            packets.append(pkt)
        return packets

    def generate_data_exfiltration(self, count: int = 40, exfil_server: str = "198.51.100.99") -> List[Packet]:
        """Generates large forward byte transfer with minimal backward response (FR5: Data Exfiltration)."""
        packets = []
        base_time = time.time()
        src_ip = f"{self.src_subnet}.180"
        sport = 60100
        
        # Heavy outbound payloads
        for i in range(count):
            t_curr = base_time + (i * 0.02)
            outbound_data = b"CONFIDENTIAL_EXFILTRATED_DATA_CHUNK_BLOCK_" + (b"A" * 1200)
            pkt = Ether()/IP(src=src_ip, dst=exfil_server)/TCP(sport=sport, dport=443, flags="PA")/Raw(outbound_data)
            pkt.time = t_curr
            packets.append(pkt)
            
            # Tiny ACK response from server every 5 packets
            if i % 5 == 0:
                ack_pkt = Ether()/IP(src=exfil_server, dst=src_ip)/TCP(sport=443, dport=sport, flags="A")
                ack_pkt.time = t_curr + 0.002
                packets.append(ack_pkt)
                
        return packets

    def generate_all_attack_categories(self) -> Dict[str, List[Packet]]:
        """Generates dataset dictionary mapping ground truth label to list of synthetic packets."""
        return {
            "ddos": self.generate_ddos_flood(),
            "c2_beaconing": self.generate_c2_beaconing(),
            "dga_dns_tunneling": self.generate_dga_dns_tunneling(),
            "malware_tls": self.generate_malware_tls(),
            "port_scan": self.generate_port_scan(),
            "data_exfiltration": self.generate_data_exfiltration()
        }

    def export_synthetic_pcap(self, output_pcap: str) -> str:
        """Generates all 6 attack types and exports to a single labeled PCAP file."""
        all_attacks = self.generate_all_attack_categories()
        combined_packets = []
        for label, pkts in all_attacks.items():
            combined_packets.extend(pkts)
        
        # Sort chronologically by packet timestamp
        combined_packets.sort(key=lambda p: float(p.time) if hasattr(p, 'time') else 0.0)
        wrpcap(output_pcap, combined_packets)
        return output_pcap
