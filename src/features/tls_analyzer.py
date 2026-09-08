"""
TLS & JA3/JA3S Handshake Metadata & Fingerprint Extractor (FR3).
Parses TLS ClientHello and ServerHello unencrypted handshake frames.
"""

import hashlib
from typing import Dict, Any, List, Optional
from scapy.all import Packet, Raw, TCP

class TLSAnalyzer:
    @staticmethod
    def _to_md5(text: str) -> str:
        if not text:
            return ""
        return hashlib.md5(text.encode('utf-8')).hexdigest()

    def extract_tls_info(self, packets: List[Packet]) -> Dict[str, Any]:
        """
        Scans TCP packets in flow for TLS handshake records (Content Type 22).
        Extracts SNI and produces JA3 / JA3S hashes from handshake fields.
        """
        has_tls = False
        sni_domain = ""
        ja3_hash = ""
        ja3s_hash = ""
        tls_version = ""
        cipher_suites_count = 0

        for pkt in packets:
            if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
                continue

            payload = bytes(pkt[Raw])
            if len(payload) < 6:
                continue

            # Check for TLS Handshake record (ContentType=22 (0x16))
            if payload[0] == 0x16:
                has_tls = True
                record_version = f"0x{payload[1]:02x}{payload[2]:02x}"
                tls_version = record_version

                handshake_type = payload[5]
                # Handshake Type 1 = ClientHello
                if handshake_type == 1 and not ja3_hash:
                    sni, ciphers_cnt, ja3_str = self._parse_client_hello(payload[5:])
                    if sni:
                        sni_domain = sni
                    if ciphers_cnt > 0:
                        cipher_suites_count = ciphers_cnt
                    if ja3_str:
                        ja3_hash = self._to_md5(ja3_str)

                # Handshake Type 2 = ServerHello
                elif handshake_type == 2 and not ja3s_hash:
                    ja3s_str = self._parse_server_hello(payload[5:])
                    if ja3s_str:
                        ja3s_hash = self._to_md5(ja3s_str)

        return {
            "has_tls": has_tls,
            "sni_domain": sni_domain,
            "ja3_fingerprint": ja3_hash,
            "ja3s_fingerprint": ja3s_hash,
            "tls_version": tls_version,
            "cipher_suites_count": cipher_suites_count
        }

    def _parse_client_hello(self, body: bytes) -> tuple:
        """Parses ClientHello bytes for SNI, cipher count, and JA3 string representation."""
        try:
            if len(body) < 38:
                return "", 0, ""
            
            # Extract Client Version (bytes 4-5 of handshake body)
            client_ver = int.from_bytes(body[4:6], 'big')
            
            # Session ID Length (byte 38)
            sess_id_len = body[38]
            idx = 39 + sess_id_len
            
            # Cipher Suites Length
            if idx + 2 > len(body):
                return "", 0, f"{client_ver},,,,"
            ciphers_len = int.from_bytes(body[idx:idx+2], 'big')
            ciphers_cnt = ciphers_len // 2
            
            cipher_list = []
            c_start = idx + 2
            for c in range(0, ciphers_len, 2):
                if c_start + c + 2 <= len(body):
                    val = int.from_bytes(body[c_start+c:c_start+c+2], 'big')
                    cipher_list.append(str(val))
            
            idx = c_start + ciphers_len
            # Compression Methods
            if idx < len(body):
                comp_len = body[idx]
                idx += 1 + comp_len

            # Extensions
            ext_list = []
            sni_name = ""
            if idx + 2 <= len(body):
                ext_total_len = int.from_bytes(body[idx:idx+2], 'big')
                idx += 2
                e_end = idx + ext_total_len
                while idx + 4 <= min(len(body), e_end):
                    ext_type = int.from_bytes(body[idx:idx+2], 'big')
                    ext_len = int.from_bytes(body[idx+2:idx+4], 'big')
                    ext_list.append(str(ext_type))
                    
                    # SNI Extension (Type 0)
                    if ext_type == 0 and idx + 4 + ext_len <= len(body):
                        sni_data = body[idx+4:idx+4+ext_len]
                        if len(sni_data) > 5:
                            # SNI name length
                            name_len = int.from_bytes(sni_data[3:5], 'big')
                            sni_name = sni_data[5:5+name_len].decode('utf-8', errors='ignore')

                    idx += 4 + ext_len

            ja3_str = f"{client_ver},{'-'.join(cipher_list)},{'-'.join(ext_list)},,"
            return sni_name, ciphers_cnt, ja3_str
        except Exception:
            return "", 0, ""

    def _parse_server_hello(self, body: bytes) -> str:
        """Parses ServerHello bytes for JA3S string representation."""
        try:
            if len(body) < 38:
                return ""
            server_ver = int.from_bytes(body[4:6], 'big')
            sess_id_len = body[38]
            idx = 39 + sess_id_len
            
            cipher_chosen = ""
            if idx + 2 <= len(body):
                val = int.from_bytes(body[idx:idx+2], 'big')
                cipher_chosen = str(val)
                idx += 2

            # Compression method
            idx += 1

            ext_list = []
            if idx + 2 <= len(body):
                ext_total_len = int.from_bytes(body[idx:idx+2], 'big')
                idx += 2
                e_end = idx + ext_total_len
                while idx + 4 <= min(len(body), e_end):
                    ext_type = int.from_bytes(body[idx:idx+2], 'big')
                    ext_len = int.from_bytes(body[idx+2:idx+4], 'big')
                    ext_list.append(str(ext_type))
                    idx += 4 + ext_len

            return f"{server_ver},{cipher_chosen},{'-'.join(ext_list)}"
        except Exception:
            return ""
