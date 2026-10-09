"""
RogueByte WhatsApp Forensics Ultimate v2.0 - Public & Private IP Analysis Engine
Brand: RogueByteOfficial
"""

import ipaddress
import re
from typing import List, Dict, Any, Optional, Set, Tuple
from datetime import datetime, timezone
from pathlib import Path

from roguebyte_forensics.network.models import (
    IPRecord,
    IPClassification,
    ASNInfo,
    GeolocationEstimate,
    IPReputationInfo
)
from roguebyte_forensics.network.whois_asn import NetworkOwnershipResolver


IPV4_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
IPV6_REGEX = re.compile(
    r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|"
    r"\b(?:[A-Fa-f0-9]{1,4}:){1,7}:[A-Fa-f0-9]{1,4}\b|"
    r"\b::(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{1,4}\b"
)


class IPAddressAnalyzer:
    """Forensic engine for analyzing, classifying, and attributing IP addresses."""

    def __init__(self, offline_mode: bool = True):
        self.offline_mode = offline_mode
        self.records: Dict[str, IPRecord] = {}

    @staticmethod
    def classify_ip(ip_str: str) -> Tuple[Optional[IPClassification], str]:
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return None, "Invalid"

        family = "IPv4" if addr.version == 4 else "IPv6"

        if addr.is_loopback:
            return IPClassification.LOOPBACK, family
        elif addr.is_link_local:
            return IPClassification.LINK_LOCAL, family
        elif addr.is_private:
            return IPClassification.PRIVATE, family
        elif addr.is_multicast:
            return IPClassification.MULTICAST, family
        elif addr.is_reserved:
            return IPClassification.RESERVED, family
        elif addr.is_global:
            return IPClassification.PUBLIC, family
        else:
            return IPClassification.SPECIAL_PURPOSE, family

    def ingest_ip(
        self,
        ip_str: str,
        source_file: str,
        timestamp_utc: Optional[str] = None,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
        packet_num: Optional[int] = None
    ) -> Optional[IPRecord]:
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return None

        clean_ip = str(addr)
        classification, family = self.classify_ip(clean_ip)

        if clean_ip in self.records:
            # Update existing record
            rec = self.records[clean_ip]
            if timestamp_utc:
                if not rec.first_seen_utc or timestamp_utc < rec.first_seen_utc:
                    rec.first_seen_utc = timestamp_utc
                if not rec.last_seen_utc or timestamp_utc > rec.last_seen_utc:
                    rec.last_seen_utc = timestamp_utc
            if protocol and protocol not in rec.associated_protocols:
                rec.associated_protocols.append(protocol)
            if port and port not in rec.associated_ports:
                rec.associated_ports.append(port)
            if packet_num and packet_num not in rec.packet_references:
                rec.packet_references.append(packet_num)
            return rec

        # Enrich with ASN & Geo
        asn = NetworkOwnershipResolver.lookup_asn(clean_ip)
        geo = NetworkOwnershipResolver.lookup_geolocation(clean_ip)
        rep = NetworkOwnershipResolver.check_reputation(clean_ip)

        new_rec = IPRecord(
            ip_address=clean_ip,
            address_family=family,
            classification=classification,
            source_file=source_file,
            first_seen_utc=timestamp_utc,
            last_seen_utc=timestamp_utc,
            packet_references=[packet_num] if packet_num else [],
            associated_protocols=[protocol] if protocol else [],
            associated_ports=[port] if port else [],
            asn_info=asn,
            geolocation=geo,
            reputation=rep
        )

        self.records[clean_ip] = new_rec
        return new_rec

    def extract_ips_from_buffer(self, buffer: bytes, source_name: str) -> List[IPRecord]:
        """Scans raw binary or text buffers for IPv4 and IPv6 strings."""
        extracted = []
        try:
            text = buffer.decode("utf-8", errors="ignore")
        except Exception:
            return extracted

        # Find IPv4
        for match in IPV4_REGEX.finditer(text):
            ip_str = match.group(0)
            rec = self.ingest_ip(ip_str, source_file=source_name)
            if rec and rec not in extracted:
                extracted.append(rec)

        # Find IPv6
        for match in IPV6_REGEX.finditer(text):
            ip_str = match.group(0)
            rec = self.ingest_ip(ip_str, source_file=source_name)
            if rec and rec not in extracted:
                extracted.append(rec)

        return extracted

    def get_public_ips(self) -> List[IPRecord]:
        return [r for r in self.records.values() if r.classification == IPClassification.PUBLIC]

    def get_private_ips(self) -> List[IPRecord]:
        return [r for r in self.records.values() if r.classification == IPClassification.PRIVATE]

    def to_dict_list(self) -> List[Dict[str, Any]]:
        results = []
        for r in self.records.values():
            item = {
                "ip_address": r.ip_address,
                "family": r.address_family,
                "classification": r.classification.value,
                "source_file": r.source_file,
                "first_seen_utc": r.first_seen_utc,
                "last_seen_utc": r.last_seen_utc,
                "packet_references": r.packet_references,
                "protocols": r.associated_protocols,
                "ports": r.associated_ports,
                "attribution_limitations": r.attribution_limitations
            }
            if r.asn_info:
                item["asn"] = {
                    "asn": r.asn_info.asn,
                    "org": r.asn_info.organization,
                    "as_name": r.asn_info.as_name,
                    "country": r.asn_info.country_code,
                    "is_meta": r.asn_info.is_meta_infrastructure
                }
            if r.geolocation:
                item["geo"] = {
                    "country": r.geolocation.country,
                    "region": r.geolocation.region,
                    "city": r.geolocation.city,
                    "disclaimer": r.geolocation.disclaimer
                }
            results.append(item)
        return results
