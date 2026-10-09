"""
RogueByte WhatsApp Forensics Ultimate v2.0 - Network Forensic Models
Brand: RogueByteOfficial
License: Proprietary / Educational & Lawful Digital Forensics
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any


class IPClassification(str, Enum):
    PUBLIC = "PUBLIC"                    # Globally routable Internet address
    PRIVATE = "PRIVATE"                  # RFC 1918 / RFC 4193 private network address
    LOOPBACK = "LOOPBACK"                # 127.0.0.0/8 or ::1
    LINK_LOCAL = "LINK_LOCAL"            # 169.254.0.0/16 or fe80::/10
    MULTICAST = "MULTICAST"              # 224.0.0.0/4 or ff00::/8
    RESERVED = "RESERVED"                # IETF reserved / future use
    SPECIAL_PURPOSE = "SPECIAL_PURPOSE"  # Carrier-grade NAT (100.64.0.0/10), benchmark, etc.


class CallCorrelationClass(str, Enum):
    """
    Forensic classification for WhatsApp call traffic attribution.
    Strictly defined to prevent false conclusions about peer IP attribution.
    """
    OBSERVED_ENDPOINT = "OBSERVED_ENDPOINT"
    POSSIBLE_CALL_ASSOCIATION = "POSSIBLE_CALL_ASSOCIATION"
    IDENTIFIED_SERVICE_INFRASTRUCTURE = "IDENTIFIED_SERVICE_INFRASTRUCTURE"
    REMOTE_PARTICIPANT_IP_UNCONFIRMED = "REMOTE_PARTICIPANT_IP_UNCONFIRMED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class ProtocolType(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    DNS = "DNS"
    TLS = "TLS"
    STUN_TURN = "STUN/TURN"
    OTHER = "OTHER"


@dataclass
class ASNInfo:
    asn: int
    as_name: str
    organization: str
    country_code: str
    cidr_prefix: str
    source_attribution: str = "RogueByte Internal Autonomous System Mapping DB v2.0"
    is_hosting_or_cloud: bool = False
    is_meta_infrastructure: bool = False


@dataclass
class GeolocationEstimate:
    country: str
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    source_database: str = "RogueByte Offline MaxMind GeoIP Lite Reference"
    database_version: str = "2026-Q1"
    disclaimer: str = (
        "IP geolocation is an estimate of network location. "
        "It does not establish a person's exact physical location."
    )


@dataclass
class IPReputationInfo:
    threat_score: int = 0               # 0 to 100
    is_flagged_proxy: bool = False
    is_flagged_vpn: bool = False
    is_flagged_tor_exit: bool = False
    is_flagged_botnet: bool = False
    categories: List[str] = field(default_factory=list)
    source_provider: str = "Offline Threat Intelligence Feed"
    lookup_timestamp_utc: str = ""
    disclaimer: str = (
        "Reputation intelligence represents third-party historical observations "
        "and does not constitute direct evidence of malicious behavior by the user."
    )


@dataclass
class IPRecord:
    ip_address: str
    address_family: str                 # "IPv4" or "IPv6"
    classification: IPClassification
    source_file: str
    first_seen_utc: Optional[str] = None
    last_seen_utc: Optional[str] = None
    packet_references: List[int] = field(default_factory=list)
    associated_protocols: List[str] = field(default_factory=list)
    associated_ports: List[int] = field(default_factory=list)
    asn_info: Optional[ASNInfo] = None
    geolocation: Optional[GeolocationEstimate] = None
    reputation: Optional[IPReputationInfo] = None
    attribution_limitations: str = (
        "An observed IP address does not establish identity of a person without "
        "ISP subscriber records and corroborating forensic evidence."
    )


@dataclass
class NetworkFlow:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: ProtocolType
    packet_count: int
    byte_count: int
    start_time_utc: str
    end_time_utc: str
    duration_seconds: float
    start_timestamp_epoch: float
    end_timestamp_epoch: float
    service_hint: Optional[str] = None
    tcp_flags_observed: List[str] = field(default_factory=list)
    is_incomplete_capture: bool = False


@dataclass
class DNSRecord:
    query_id: int
    timestamp_utc: str
    query_name: str
    query_type: str                     # "A", "AAAA", "CNAME", etc.
    response_ips: List[str] = field(default_factory=list)
    response_code: str = "NOERROR"
    packet_number: int = 0
    source_ip: str = ""
    destination_ip: str = ""


@dataclass
class CallNetworkCorrelation:
    call_id: str
    call_type: str                      # "voice" or "video"
    call_start_utc: str
    call_end_utc: str
    call_duration_seconds: int
    participant_jid: str
    candidate_flows: List[NetworkFlow]
    observed_endpoints: List[IPRecord]
    classification: CallCorrelationClass
    attribution_disclaimer: str
    examiner_rationale: str


@dataclass
class MessageNetworkCorrelation:
    message_id: str
    message_timestamp_utc: str
    sender_jid: str
    remote_jid: str
    candidate_flows: List[NetworkFlow]
    time_delta_seconds: float
    confidence_level: str               # "HIGH_TEMPORAL_ALIGNMENT", "MODERATE", "LOW"
    attribution_disclaimer: str
    examiner_rationale: str
