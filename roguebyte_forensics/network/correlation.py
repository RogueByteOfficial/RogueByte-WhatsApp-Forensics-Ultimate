"""
RogueByte WhatsApp Forensics Ultimate v2.0 - WhatsApp Network Correlation Subsystem
Brand: RogueByteOfficial
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from roguebyte_forensics.network.models import (
    CallNetworkCorrelation,
    CallCorrelationClass,
    MessageNetworkCorrelation,
    NetworkFlow,
    IPRecord,
    ProtocolType
)
from roguebyte_forensics.network.ip_analyzer import IPAddressAnalyzer
from roguebyte_forensics.network.whois_asn import NetworkOwnershipResolver
from roguebyte_forensics.core.models import MessageRecord


CALL_ATTRIBUTION_DISCLAIMER = (
    "FORENSIC EVIDENTIARY LIMITATION: WhatsApp voice and video calls utilize "
    "intermediary infrastructure, STUN/TURN relays, carrier-grade NAT, and VPNs. "
    "Encrypted RTP/SRTP traffic observed during a call window does NOT establish "
    "that an observed IP address belongs directly to the remote participant without "
    "carrier subscriber logs and lawful intercept verification."
)

MESSAGE_ATTRIBUTION_DISCLAIMER = (
    "FORENSIC EVIDENTIARY LIMITATION: WhatsApp text communications are routed "
    "through centralized Meta edge infrastructure (ports 443/5222). Observed server "
    "IP addresses belong to Meta Platforms network infrastructure and do NOT identify "
    "the individual user or remote participant."
)


class NetworkCorrelationEngine:
    """Correlates mobile WhatsApp database records with observable network flows."""

    def __init__(self, flows: List[NetworkFlow], ip_records: Dict[str, IPRecord]):
        self.flows = flows
        self.ip_records = ip_records

    def correlate_call(
        self,
        call_id: str,
        participant_jid: str,
        start_epoch: float,
        end_epoch: float,
        call_type: str = "voice"
    ) -> CallNetworkCorrelation:
        """
        Correlates a documented WhatsApp call window with network flows.
        Tolerance window: +/- 5.0 seconds for signaling setup and teardown.
        """
        tolerance_sec = 5.0
        window_start = start_epoch - tolerance_sec
        window_end = end_epoch + tolerance_sec
        duration_sec = max(1, int(end_epoch - start_epoch))

        start_dt = datetime.fromtimestamp(start_epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"
        end_dt = datetime.fromtimestamp(end_epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"

        candidate_flows: List[NetworkFlow] = []
        observed_endpoints: List[IPRecord] = []

        for flow in self.flows:
            # Check overlap between flow lifetime and call window
            if flow.start_timestamp_epoch <= window_end and flow.end_timestamp_epoch >= window_start:
                # Potential candidate flow
                candidate_flows.append(flow)

                # Register endpoints
                for ip in (flow.src_ip, flow.dst_ip):
                    if ip in self.ip_records and self.ip_records[ip] not in observed_endpoints:
                        observed_endpoints.append(self.ip_records[ip])

        # Evaluate forensic classification
        has_meta_infra = False
        has_media_candidates = False

        for f in candidate_flows:
            if f.protocol in (ProtocolType.STUN_TURN, ProtocolType.UDP) and f.byte_count > 5000:
                has_media_candidates = True
            asn = NetworkOwnershipResolver.lookup_asn(f.dst_ip) or NetworkOwnershipResolver.lookup_asn(f.src_ip)
            if asn and asn.is_meta_infrastructure:
                has_meta_infra = True

        if not candidate_flows:
            classification = CallCorrelationClass.INSUFFICIENT_EVIDENCE
            rationale = "No network flows were captured during the documented call time window."
        elif has_meta_infra and has_media_candidates:
            classification = CallCorrelationClass.IDENTIFIED_SERVICE_INFRASTRUCTURE
            rationale = (
                f"Candidate UDP/STUN flows active during the call window ({duration_sec}s) "
                f"route through documented Meta Platforms infrastructure (AS32934). "
                f"Endpoints represent relay/TURN servers rather than a direct peer IP."
            )
        elif has_media_candidates:
            classification = CallCorrelationClass.REMOTE_PARTICIPANT_IP_UNCONFIRMED
            rationale = (
                "UDP flows with real-time media characteristics observed during call window, "
                "but capture does not establish whether the endpoint is a peer or third-party relay."
            )
        else:
            classification = CallCorrelationClass.POSSIBLE_CALL_ASSOCIATION
            rationale = "Candidate flows observed during call window, but traffic volume is insufficient to confirm real-time media."

        return CallNetworkCorrelation(
            call_id=call_id,
            call_type=call_type,
            call_start_utc=start_dt,
            call_end_utc=end_dt,
            call_duration_seconds=duration_sec,
            participant_jid=participant_jid,
            candidate_flows=candidate_flows,
            observed_endpoints=observed_endpoints,
            classification=classification,
            attribution_disclaimer=CALL_ATTRIBUTION_DISCLAIMER,
            examiner_rationale=rationale
        )

    def correlate_message(self, message: MessageRecord) -> MessageNetworkCorrelation:
        """
        Correlates a text message event with observable signaling flows.
        Tolerance window: +/- 3.0 seconds around message timestamp epoch.
        """
        msg_epoch = message.timestamp_ms / 1000.0 if message.timestamp_ms > 0 else 0
        tolerance_sec = 3.0
        candidate_flows: List[NetworkFlow] = []
        best_delta = 999.0

        if msg_epoch > 0:
            for flow in self.flows:
                # Check signaling ports (443 TLS, 5222 WhatsApp Noise protocol)
                if flow.dst_port in (443, 5222) or flow.src_port in (443, 5222):
                    if (flow.start_timestamp_epoch - tolerance_sec) <= msg_epoch <= (flow.end_timestamp_epoch + tolerance_sec):
                        candidate_flows.append(flow)
                        delta = abs(flow.start_timestamp_epoch - msg_epoch)
                        if delta < best_delta:
                            best_delta = delta

        confidence = "HIGH_TEMPORAL_ALIGNMENT" if (candidate_flows and best_delta < 1.0) else "MODERATE" if candidate_flows else "LOW"
        rationale = (
            f"Found {len(candidate_flows)} candidate TCP signaling flow(s) to WhatsApp edge infrastructure "
            f"within temporal correlation window (Delta: {best_delta:.2f}s)."
            if candidate_flows else "No concurrent signaling traffic identified within window."
        )

        return MessageNetworkCorrelation(
            message_id=message.message_id,
            message_timestamp_utc=message.timestamp_utc,
            sender_jid=message.sender_jid,
            remote_jid=message.remote_jid,
            candidate_flows=candidate_flows,
            time_delta_seconds=best_delta if candidate_flows else 0.0,
            confidence_level=confidence,
            attribution_disclaimer=MESSAGE_ATTRIBUTION_DISCLAIMER,
            examiner_rationale=rationale
        )
