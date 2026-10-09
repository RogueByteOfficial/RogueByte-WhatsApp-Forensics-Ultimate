"""
RogueByte WhatsApp Forensics Ultimate v2.0 - ASN, Geolocation & Reputation Module
Brand: RogueByteOfficial
"""

import ipaddress
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from roguebyte_forensics.network.models import (
    ASNInfo,
    GeolocationEstimate,
    IPReputationInfo,
    IPClassification
)


# Known Autonomous System Subnet Mappings (Offline Database)
OFFLINE_ASN_RANGES = [
    # Meta Platforms / WhatsApp Primary Infrastructure
    ("157.240.0.0/16", 32934, "FACEBOOK", "Meta Platforms, Inc. (WhatsApp Infrastructure)", "US", True, True),
    ("31.13.64.0/18", 32934, "FACEBOOK", "Meta Platforms, Inc. (WhatsApp Relays)", "US", True, True),
    ("129.134.0.0/16", 32934, "FACEBOOK", "Meta Platforms, Inc. (WhatsApp Media Servers)", "US", True, True),
    ("179.60.192.0/22", 32934, "FACEBOOK", "Meta Platforms, Inc. (Edge POP)", "US", True, True),
    ("185.89.218.0/23", 32934, "FACEBOOK", "Meta Platforms, Inc. (Europe Edge)", "IE", True, True),
    ("2a03:2880::/32", 32934, "FACEBOOK", "Meta Platforms, Inc. IPv6 Infrastructure", "US", True, True),
    
    # Cloudflare Anycast
    ("104.16.0.0/12", 13335, "CLOUDFLARENET", "Cloudflare, Inc.", "US", True, False),
    ("172.64.0.0/13", 13335, "CLOUDFLARENET", "Cloudflare, Inc.", "US", True, False),
    ("1.1.1.1/32", 13335, "CLOUDFLARENET", "Cloudflare 1.1.1.1 Public DNS", "US", True, False),
    
    # Google LLC
    ("8.8.8.8/32", 15169, "GOOGLE", "Google LLC Public DNS", "US", True, False),
    ("8.8.4.4/32", 15169, "GOOGLE", "Google LLC Public DNS", "US", True, False),
    ("142.250.0.0/15", 15169, "GOOGLE", "Google LLC Global Infrastructure", "US", True, False),
    
    # Amazon Web Services
    ("52.0.0.0/11", 16509, "AMAZON-02", "Amazon.com, Inc. (AWS Cloud)", "US", True, False),
    ("54.0.0.0/12", 16509, "AMAZON-02", "Amazon.com, Inc. (AWS Cloud)", "US", True, False),
    
    # Swisscom / Swiss Financial Network (Matter RB-2026-089)
    ("195.186.0.0/16", 3303, "SWISSCOM", "Swisscom Enterprise Services (Zurich)", "CH", False, False),
    ("194.209.0.0/16", 3303, "SWISSCOM", "Swisscom Core IP Network", "CH", False, False),
    
    # Residential & Mobile Carrier Networks
    ("172.56.0.0/12", 21928, "T-MOBILE-AS21928", "T-Mobile USA, Inc. Mobile Wireless", "US", False, False),
    ("107.77.0.0/16", 20057, "ATT-MOBILITY-LLC", "AT&T Mobility LLC Cellular", "US", False, False),
    ("82.165.0.0/16", 8560, "IONOS-AS", "IONOS SE Hosting Services", "DE", True, False),
]

OFFLINE_GEO_DATABASE = {
    "157.240.22.35": ("United States", "California", "Menlo Park", 37.4530, -122.1817),
    "157.240.199.60": ("United States", "Virginia", "Ashburn", 39.0438, -77.4874),
    "31.13.86.36": ("Ireland", "Leinster", "Dublin", 53.3498, -6.2603),
    "195.186.210.88": ("Switzerland", "Zurich", "Zurich", 47.3769, 8.5417),
    "104.16.249.249": ("United States", "California", "San Francisco", 37.7749, -122.4194),
    "8.8.8.8": ("United States", "California", "Mountain View", 37.4223, -122.0848),
    "172.56.21.90": ("United States", "Washington", "Seattle", 47.6062, -122.3321),
}


class NetworkOwnershipResolver:
    """Resolves Autonomous System (ASN), BGP prefix, and registered organization."""
    
    @staticmethod
    def lookup_asn(ip_str: str) -> Optional[ASNInfo]:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return None

        # Private / non-routable check
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
            return ASNInfo(
                asn=0,
                as_name="NON_ROUTABLE",
                organization="Private / Reserved Special Purpose Network (IANA)",
                country_code="--",
                cidr_prefix=f"{ip_str}/32" if ip_obj.version == 4 else f"{ip_str}/128",
                is_hosting_or_cloud=False,
                is_meta_infrastructure=False
            )

        for cidr, asn, as_name, org, country, is_cloud, is_meta in OFFLINE_ASN_RANGES:
            try:
                network = ipaddress.ip_network(cidr)
                if ip_obj in network:
                    return ASNInfo(
                        asn=asn,
                        as_name=as_name,
                        organization=org,
                        country_code=country,
                        cidr_prefix=cidr,
                        is_hosting_or_cloud=is_cloud,
                        is_meta_infrastructure=is_meta
                    )
            except ValueError:
                continue

        # Fallback for unknown public IPs
        return ASNInfo(
            asn=64512,  # Private ASN range indicator
            as_name="UNSPECIFIED_PUBLIC_AS",
            organization=f"Public Internet Autonomous System (Prefix unknown in offline DB)",
            country_code="XX",
            cidr_prefix=f"{ip_str}/32",
            is_hosting_or_cloud=False,
            is_meta_infrastructure=False
        )

    @staticmethod
    def lookup_geolocation(ip_str: str) -> Optional[GeolocationEstimate]:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return None

        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            return None  # Do not geolocate private IPs!

        # Check exact IP or subnet
        if ip_str in OFFLINE_GEO_DATABASE:
            country, reg, city, lat, lon = OFFLINE_GEO_DATABASE[ip_str]
            return GeolocationEstimate(
                country=country,
                region=reg,
                city=city,
                latitude=lat,
                longitude=lon
            )

        # Country estimation based on ASN lookup
        asn_info = NetworkOwnershipResolver.lookup_asn(ip_str)
        if asn_info and asn_info.country_code != "--":
            return GeolocationEstimate(
                country=asn_info.country_code,
                region="Regional Registry Allocation",
                city=None,
                latitude=None,
                longitude=None
            )

        return None

    @staticmethod
    def check_reputation(ip_str: str) -> IPReputationInfo:
        now_utc = datetime.now(timezone.utc).isoformat()
        asn = NetworkOwnershipResolver.lookup_asn(ip_str)
        
        # Check known indicators
        is_cloud = asn.is_hosting_or_cloud if asn else False
        is_meta = asn.is_meta_infrastructure if asn else False

        categories = []
        score = 0

        if is_meta:
            categories.append("Verified WhatsApp/Meta Infrastructure")
            score = 0
        elif is_cloud:
            categories.append("Data Center / Hosting Provider")
            score = 15
        elif ip_str == "195.186.210.88":
            categories.append("Swiss Banking / Enterprise IP Endpoint")
            score = 5

        return IPReputationInfo(
            threat_score=score,
            is_flagged_proxy=False,
            is_flagged_vpn=False,
            is_flagged_tor_exit=False,
            is_flagged_botnet=False,
            categories=categories,
            lookup_timestamp_utc=now_utc
        )
