"""
RogueByte WhatsApp Forensics Ultimate v2.0 - PCAP & PCAPNG Forensic Packet Parser
Brand: RogueByteOfficial
"""

import struct
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional, Set

from roguebyte_forensics.network.models import (
    NetworkFlow,
    ProtocolType,
    DNSRecord,
    IPRecord
)
from roguebyte_forensics.network.ip_analyzer import IPAddressAnalyzer


# Standard PCAP Magic Numbers
PCAP_MAGIC_BE = 0xa1b2c3d4
PCAP_MAGIC_LE = 0xd4c3b2a1
PCAP_NANO_BE = 0xa1b23c4d
PCAP_NANO_LE = 0x4d3cb2a1

# PCAPNG Block Types
PCAPNG_SHB_MAGIC = 0x0A0D0D0A
PCAPNG_IDB_MAGIC = 0x00000001
PCAPNG_EPB_MAGIC = 0x00000006
PCAPNG_SPB_MAGIC = 0x00000003


class PacketAnalysisEngine:
    """Forensic parser for PCAP and PCAPNG traffic capture files."""

    def __init__(self, pcap_path: str):
        self.pcap_path = Path(pcap_path)
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"Network capture file not found: {pcap_path}")

        self.ip_analyzer = IPAddressAnalyzer()
        self.flows: Dict[str, NetworkFlow] = {}
        self.dns_records: List[DNSRecord] = []
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.capture_format: str = "Unknown"
        self.is_truncated: bool = False

    def parse(self) -> Dict[str, Any]:
        """Auto-detects format (PCAP vs PCAPNG) and parses all packets."""
        with open(self.pcap_path, "rb") as f:
            magic_bytes = f.read(4)
            if len(magic_bytes) < 4:
                return {"error": "File smaller than 4 bytes", "valid": False}

        magic_int = struct.unpack(">I", magic_bytes)[0]
        magic_le = struct.unpack("<I", magic_bytes)[0]

        if magic_int in (PCAP_MAGIC_BE, PCAP_MAGIC_LE, PCAP_NANO_BE, PCAP_NANO_LE):
            self.capture_format = "Classic PCAP"
            return self._parse_classic_pcap()
        elif magic_int == PCAPNG_SHB_MAGIC:
            self.capture_format = "PCAPNG (Next Generation Capture)"
            return self._parse_pcapng()
        else:
            return {"error": f"Unrecognized capture magic: {magic_bytes.hex()}", "valid": False}

    def _parse_classic_pcap(self) -> Dict[str, Any]:
        with open(self.pcap_path, "rb") as f:
            global_header = f.read(24)
            if len(global_header) < 24:
                return {"error": "Truncated PCAP header", "valid": False}

            magic = struct.unpack(">I", global_header[:4])[0]
            if magic in (PCAP_MAGIC_BE, PCAP_NANO_BE):
                endianness = ">"
                is_nano = (magic == PCAP_NANO_BE)
            else:
                endianness = "<"
                is_nano = (struct.unpack("<I", global_header[:4])[0] == PCAP_NANO_LE)

            snaplen = struct.unpack(f"{endianness}I", global_header[16:20])[0]
            linktype = struct.unpack(f"{endianness}I", global_header[20:24])[0]

            packet_num = 0

            while True:
                packet_header = f.read(16)
                if len(packet_header) < 16:
                    break

                packet_num += 1
                ts_sec = struct.unpack(f"{endianness}I", packet_header[:4])[0]
                ts_subsec = struct.unpack(f"{endianness}I", packet_header[4:8])[0]
                caplen = struct.unpack(f"{endianness}I", packet_header[8:12])[0]
                wirelen = struct.unpack(f"{endianness}I", packet_header[12:16])[0]

                packet_bytes = f.read(caplen)
                if len(packet_bytes) < caplen:
                    self.is_truncated = True
                    break

                # Calculate UTC timestamp
                epoch = ts_sec + (ts_subsec / 1e9 if is_nano else ts_subsec / 1e6)
                dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
                utc_str = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"

                self.total_packets += 1
                self.total_bytes += wirelen

                self._process_raw_packet(packet_bytes, linktype, packet_num, utc_str, epoch, wirelen)

        return self._generate_summary()

    def _parse_pcapng(self) -> Dict[str, Any]:
        with open(self.pcap_path, "rb") as f:
            packet_num = 0
            endianness = "="

            while True:
                header = f.read(8)
                if len(header) < 8:
                    break

                block_type, block_len = struct.unpack("=II", header)
                if block_type == PCAPNG_SHB_MAGIC:
                    # Section Header Block
                    bom = f.read(4)
                    if bom == b"\x1a\x2b\x3c\x4d":
                        endianness = ">"
                    else:
                        endianness = "<"
                    f.seek(-4, 1)

                body_len = block_len - 8
                if body_len < 0:
                    break
                block_body = f.read(body_len)
                if len(block_body) < body_len:
                    self.is_truncated = True
                    break

                if block_type == PCAPNG_EPB_MAGIC and len(block_body) >= 20:
                    packet_num += 1
                    # Interface ID (4), Timestamp High (4), Timestamp Low (4), CapLen (4), OrigLen (4)
                    ts_hi = struct.unpack(f"{endianness}I", block_body[4:8])[0]
                    ts_lo = struct.unpack(f"{endianness}I", block_body[8:12])[0]
                    caplen = struct.unpack(f"{endianness}I", block_body[12:16])[0]
                    origlen = struct.unpack(f"{endianness}I", block_body[16:20])[0]

                    ts_raw = (ts_hi << 32) | ts_lo
                    epoch = ts_raw / 1e6  # Microsecond resolution default
                    try:
                        dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
                        utc_str = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"
                    except Exception:
                        utc_str = "EPOCH_CONVERSION_ERROR"

                    pkt_data = block_body[20:20 + caplen]
                    self.total_packets += 1
                    self.total_bytes += origlen

                    self._process_raw_packet(pkt_data, 1, packet_num, utc_str, epoch, origlen)

        return self._generate_summary()

    def _process_raw_packet(
        self,
        data: bytes,
        linktype: int,
        pkt_num: int,
        utc_str: str,
        epoch: float,
        wirelen: int
    ):
        ip_offset = 0

        # Link Layer Handling
        if linktype == 1:  # Ethernet
            if len(data) < 14:
                return
            eth_proto = struct.unpack(">H", data[12:14])[0]
            ip_offset = 14
            if eth_proto == 0x8100:  # 802.1Q VLAN Tagged
                if len(data) < 18:
                    return
                eth_proto = struct.unpack(">H", data[16:18])[0]
                ip_offset = 18

            if eth_proto == 0x0800:
                self._parse_ipv4(data[ip_offset:], pkt_num, utc_str, epoch, wirelen)
            elif eth_proto == 0x86DD:
                self._parse_ipv6(data[ip_offset:], pkt_num, utc_str, epoch, wirelen)
        elif linktype in (101, 12):  # Raw IP
            if len(data) > 0:
                version = (data[0] >> 4)
                if version == 4:
                    self._parse_ipv4(data, pkt_num, utc_str, epoch, wirelen)
                elif version == 6:
                    self._parse_ipv6(data, pkt_num, utc_str, epoch, wirelen)

    def _parse_ipv4(self, ip_bytes: bytes, pkt_num: int, utc_str: str, epoch: float, wirelen: int):
        if len(ip_bytes) < 20:
            return

        ihl = (ip_bytes[0] & 0x0F) * 4
        protocol_num = ip_bytes[9]
        src_ip = socket.inet_ntoa(ip_bytes[12:16])
        dst_ip = socket.inet_ntoa(ip_bytes[16:20])

        payload = ip_bytes[ihl:]
        self._dispatch_transport(src_ip, dst_ip, protocol_num, payload, pkt_num, utc_str, epoch, wirelen)

    def _parse_ipv6(self, ip_bytes: bytes, pkt_num: int, utc_str: str, epoch: float, wirelen: int):
        if len(ip_bytes) < 40:
            return

        next_header = ip_bytes[6]
        src_ip = socket.inet_ntop(socket.AF_INET6, ip_bytes[8:24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, ip_bytes[24:40])

        payload = ip_bytes[40:]
        self._dispatch_transport(src_ip, dst_ip, next_header, payload, pkt_num, utc_str, epoch, wirelen)

    def _dispatch_transport(
        self,
        src_ip: str,
        dst_ip: str,
        proto_num: int,
        payload: bytes,
        pkt_num: int,
        utc_str: str,
        epoch: float,
        wirelen: int
    ):
        src_port = 0
        dst_port = 0
        proto_type = ProtocolType.OTHER
        tcp_flags = []

        if proto_num == 6 and len(payload) >= 20:  # TCP
            proto_type = ProtocolType.TCP
            src_port = struct.unpack(">H", payload[0:2])[0]
            dst_port = struct.unpack(">H", payload[2:4])[0]
            flags_byte = payload[13]
            if flags_byte & 0x02: tcp_flags.append("SYN")
            if flags_byte & 0x10: tcp_flags.append("ACK")
            if flags_byte & 0x01: tcp_flags.append("FIN")
            if flags_byte & 0x04: tcp_flags.append("RST")
            if flags_byte & 0x08: tcp_flags.append("PSH")

        elif proto_num == 17 and len(payload) >= 8:  # UDP
            proto_type = ProtocolType.UDP
            src_port = struct.unpack(">H", payload[0:2])[0]
            dst_port = struct.unpack(">H", payload[2:4])[0]
            udp_payload = payload[8:]

            # DNS Inspection (Port 53 or 5353)
            if src_port in (53, 5353) or dst_port in (53, 5353):
                self._parse_dns(udp_payload, pkt_num, utc_str, src_ip, dst_ip)

            # STUN / TURN check for WhatsApp Voice Calls (Port 3478 or UDP STUN magic cookie 0x2112A442)
            if (src_port == 3478 or dst_port == 3478) or (len(udp_payload) >= 8 and udp_payload[4:8] == b"\x21\x12\xa4\x42"):
                proto_type = ProtocolType.STUN_TURN

        # Register IPs
        self.ip_analyzer.ingest_ip(src_ip, self.pcap_path.name, utc_str, proto_type.value, src_port, pkt_num)
        self.ip_analyzer.ingest_ip(dst_ip, self.pcap_path.name, utc_str, proto_type.value, dst_port, pkt_num)

        # Flow Reconstruction (Bidirectional 5-tuple key)
        if src_ip <= dst_ip:
            flow_key = f"{src_ip}:{src_port}<->{dst_ip}:{dst_port}/{proto_type.value}"
        else:
            flow_key = f"{dst_ip}:{dst_port}<->{src_ip}:{src_port}/{proto_type.value}"

        # WhatsApp Service Port Heuristics
        service_hint = None
        if 443 in (src_port, dst_port):
            service_hint = "HTTPS / TLS Encrypted Signaling"
        elif 5222 in (src_port, dst_port):
            service_hint = "WhatsApp Native Messaging (Port 5222)"
        elif 3478 in (src_port, dst_port) or proto_type == ProtocolType.STUN_TURN:
            service_hint = "WhatsApp Call Media Relay (STUN/TURN)"
        elif proto_type == ProtocolType.UDP and (src_port >= 10000 or dst_port >= 10000):
            service_hint = "Candidate Real-Time Media (SRTP / Audio Flow)"

        if flow_key in self.flows:
            flow = self.flows[flow_key]
            flow.packet_count += 1
            flow.byte_count += wirelen
            flow.end_time_utc = utc_str
            flow.end_timestamp_epoch = epoch
            flow.duration_seconds = max(0.0, epoch - flow.start_timestamp_epoch)
            for f in tcp_flags:
                if f not in flow.tcp_flags_observed:
                    flow.tcp_flags_observed.append(f)
        else:
            self.flows[flow_key] = NetworkFlow(
                flow_id=f"FLOW-{len(self.flows) + 1:05d}",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto_type,
                packet_count=1,
                byte_count=wirelen,
                start_time_utc=utc_str,
                end_time_utc=utc_str,
                duration_seconds=0.0,
                start_timestamp_epoch=epoch,
                end_timestamp_epoch=epoch,
                service_hint=service_hint,
                tcp_flags_observed=tcp_flags
            )

    def _parse_dns(self, dns_bytes: bytes, pkt_num: int, utc_str: str, src_ip: str, dst_ip: str):
        if len(dns_bytes) < 12:
            return

        tx_id, flags, qdcount, ancount = struct.unpack(">HHHH", dns_bytes[:8])
        is_response = bool(flags & 0x8000)
        rcode = flags & 0x000F

        # Parse query domain name
        offset = 12
        domain_parts = []
        safety = 0
        while offset < len(dns_bytes) and safety < 20:
            safety += 1
            length = dns_bytes[offset]
            if length == 0:
                offset += 1
                break
            if length >= 192:  # Pointer compression
                offset += 2
                break
            offset += 1
            part = dns_bytes[offset:offset + length].decode("utf-8", errors="ignore")
            domain_parts.append(part)
            offset += length

        query_domain = ".".join(domain_parts)
        if not query_domain or len(query_domain) < 3:
            return

        # Simple answer extraction for Type A / AAAA
        response_ips = []
        if is_response and ancount > 0:
            # Quick scan remaining bytes for IPv4 addresses
            for i in range(offset, len(dns_bytes) - 4):
                if dns_bytes[i:i + 2] == b"\x00\x01" and dns_bytes[i + 2:i + 4] == b"\x00\x01":  # Type A, Class IN
                    ip_data = dns_bytes[i + 10:i + 14]
                    if len(ip_data) == 4:
                        try:
                            resolved_ip = socket.inet_ntoa(ip_data)
                            if resolved_ip not in response_ips:
                                response_ips.append(resolved_ip)
                        except Exception:
                            pass

        # Correlate query and response with same transaction ID
        for existing in self.dns_records:
            if existing.query_id == tx_id and existing.query_name == query_domain:
                if response_ips:
                    for ip in response_ips:
                        if ip not in existing.response_ips:
                            existing.response_ips.append(ip)
                if is_response:
                    existing.response_code = "NOERROR" if rcode == 0 else f"RCODE_{rcode}"
                return

        dns_rec = DNSRecord(
            query_id=tx_id,
            timestamp_utc=utc_str,
            query_name=query_domain,
            query_type="A" if not response_ips or "." in response_ips[0] else "AAAA",
            response_ips=response_ips,
            response_code="NOERROR" if rcode == 0 else f"RCODE_{rcode}",
            packet_number=pkt_num,
            source_ip=src_ip,
            destination_ip=dst_ip
        )
        self.dns_records.append(dns_rec)

    def _generate_summary(self) -> Dict[str, Any]:
        return {
            "valid": True,
            "capture_format": self.capture_format,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "unique_flows_reconstructed": len(self.flows),
            "dns_queries_extracted": len(self.dns_records),
            "unique_ip_addresses": len(self.ip_analyzer.records),
            "is_truncated": self.is_truncated,
            "public_ips_count": len(self.ip_analyzer.get_public_ips()),
            "private_ips_count": len(self.ip_analyzer.get_private_ips())
        }
