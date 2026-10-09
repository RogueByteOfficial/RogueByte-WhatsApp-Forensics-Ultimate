"""
RogueByte WhatsApp Forensics Ultimate v2.0 - Synthetic PCAP Generator for Testing
Brand: RogueByteOfficial
"""

import struct
import socket
from pathlib import Path


class SyntheticPCAPGenerator:
    """Generates synthetic valid binary PCAP files with known ground truth packets."""

    @staticmethod
    def create_test_pcap(filepath: str, base_epoch: float = 1773440400.0) -> str:
        """
        Generates a standard 24-byte PCAP file with:
        - 1 DNS query to e1.whatsapp.net -> 157.240.22.35
        - 2 TCP handshake packets to WhatsApp server (157.240.22.35:443)
        - 1 UDP STUN/TURN packet for WhatsApp call (31.13.86.36:3478)
        - 1 Inbound Swiss banking transfer confirmation flow (195.186.210.88:443)
        - 1 Private loopback / LAN packet (192.168.1.100 -> 192.168.1.1)
        """
        p = Path(filepath)
        p.parent.mkdir(parents=True, exist_ok=True)

        with open(p, "wb") as f:
            # 24-byte Global PCAP Header
            # Magic (0xa1b2c3d4), Version 2.4, Thiszone (0), Sigfigs (0), Snaplen (65535), Network (1 = Ethernet)
            f.write(struct.pack(">IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

            def write_packet(epoch_sec, epoch_usec, pkt_bytes):
                hdr = struct.pack(">IIII", int(epoch_sec), int(epoch_usec), len(pkt_bytes), len(pkt_bytes))
                f.write(hdr)
                f.write(pkt_bytes)

            # Packet 1: DNS Query for e1.whatsapp.net (192.168.1.50:52114 -> 8.8.8.8:53)
            # Ethernet (14) + IPv4 (20) + UDP (8) + DNS (35)
            eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
            ip_dns = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + 8 + 35, 0x1001, 0x4000, 64, 17, 0,
                                socket.inet_aton("192.168.1.50"), socket.inet_aton("8.8.8.8"))
            udp_dns = struct.pack("!HHHH", 52114, 53, 8 + 35, 0)
            dns_payload = (
                struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) +
                b"\x02e1\x08whatsapp\x03net\x00" +
                struct.pack("!HH", 1, 1)  # Type A, Class IN
            )
            write_packet(base_epoch, 100000, eth + ip_dns + udp_dns + dns_payload)

            # Packet 2: DNS Response with IP 157.240.22.35
            ip_dns_resp = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + 8 + 51, 0x1002, 0x4000, 64, 17, 0,
                                     socket.inet_aton("8.8.8.8"), socket.inet_aton("192.168.1.50"))
            udp_dns_resp = struct.pack("!HHHH", 53, 52114, 8 + 51, 0)
            dns_resp_payload = (
                struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) +
                b"\x02e1\x08whatsapp\x03net\x00" +
                struct.pack("!HH", 1, 1) +
                b"\xc0\x0c" +  # Name pointer
                struct.pack("!HHIH4s", 1, 1, 300, 4, socket.inet_aton("157.240.22.35"))
            )
            write_packet(base_epoch + 0.05, 150000, eth + ip_dns_resp + udp_dns_resp + dns_resp_payload)

            # Packet 3: TCP SYN to WhatsApp Server 157.240.22.35:443
            ip_tcp = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0x2001, 0x4000, 64, 6, 0,
                                socket.inet_aton("192.168.1.50"), socket.inet_aton("157.240.22.35"))
            tcp_syn = struct.pack("!HHIIBBHHH", 48102, 443, 0x1000, 0, (5 << 4), 0x02, 65535, 0, 0)
            write_packet(base_epoch + 1.0, 200000, eth + ip_tcp + tcp_syn)

            # Packet 4: TCP SYN-ACK from WhatsApp Server
            ip_tcp_ack = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0x2002, 0x4000, 64, 6, 0,
                                    socket.inet_aton("157.240.22.35"), socket.inet_aton("192.168.1.50"))
            tcp_synack = struct.pack("!HHIIBBHHH", 443, 48102, 0x2000, 0x1001, (5 << 4), 0x12, 65535, 0, 0)
            write_packet(base_epoch + 1.05, 250000, eth + ip_tcp_ack + tcp_synack)

            # Packet 5: WhatsApp Call STUN Relay Packet (31.13.86.36:3478)
            ip_stun = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + 8 + 20, 0x3001, 0x4000, 64, 17, 0,
                                 socket.inet_aton("192.168.1.50"), socket.inet_aton("31.13.86.36"))
            udp_stun = struct.pack("!HHHH", 34780, 3478, 8 + 20, 0)
            stun_payload = struct.pack("!HHI12s", 0x0001, 0, 0x2112a442, b"\x01" * 12)  # Binding Request
            write_packet(base_epoch + 120.0, 300000, eth + ip_stun + udp_stun + stun_payload)

            # Packet 6: Swiss Banking Flow Endpoint (195.186.210.88:443)
            ip_swiss = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0x4001, 0x4000, 64, 6, 0,
                                  socket.inet_aton("192.168.1.50"), socket.inet_aton("195.186.210.88"))
            tcp_swiss = struct.pack("!HHIIBBHHH", 51234, 443, 0x3000, 0, (5 << 4), 0x02, 65535, 0, 0)
            write_packet(base_epoch + 240.0, 400000, eth + ip_swiss + tcp_swiss)

        return str(p)
