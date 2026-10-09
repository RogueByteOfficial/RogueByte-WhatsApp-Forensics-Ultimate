"""
RogueByte WhatsApp Forensics Ultimate - Advanced Timeline Engine
Author: RogueByteOfficial
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from roguebyte_forensics.core.models import (
    MessageRecord,
    TimelineEvent,
    ConfidenceCategory
)


class ForensicTimelineEngine:
    def __init__(self, examiner_tz_offset_hours: int = 0):
        self.tz_offset_hours = examiner_tz_offset_hours
        self.events: List[TimelineEvent] = []

    def build_timeline(self, messages: List[MessageRecord], acquisition_time_ms: Optional[int] = None) -> List[TimelineEvent]:
        events = []
        now_ms = acquisition_time_ms or int(datetime.now(timezone.utc).timestamp() * 1000)

        # Sort messages by timestamp
        sorted_msgs = sorted(messages, key=lambda m: m.timestamp_ms)

        seen_timestamps = set()
        prev_msg = None

        for idx, msg in enumerate(sorted_msgs):
            ts = msg.timestamp_ms
            has_anomaly = False
            anomaly_explanation = None

            # 1. Future timestamp check
            if ts > now_ms + (86400 * 1000):  # > 24 hours into future
                has_anomaly = True
                anomaly_explanation = (
                    "Timestamp occurs in the future relative to acquisition. "
                    "Possible causes: Device system clock was manually changed, RTC battery failure, or network time drift."
                )

            # 2. Pre-WhatsApp epoch check (WhatsApp founded 2009)
            elif ts < 1230768000000 and ts > 0:  # Before Jan 1 2009
                has_anomaly = True
                anomaly_explanation = (
                    "Timestamp precedes WhatsApp product release epoch (2009). "
                    "Likely caused by device default Unix epoch reset (e.g. 1970/1980) or uninitialized clock."
                )

            # 3. Check for exact duplicate timestamps
            if ts in seen_timestamps and ts > 0:
                pass  # Concurrent events can legitimately happen
            seen_timestamps.add(ts)

            # Event summary
            action = "Sent message" if msg.is_from_me else "Received message"
            text_preview = (msg.text_content[:60] + "...") if msg.text_content and len(msg.text_content) > 60 else (msg.text_content or f"[{msg.message_type.value}]")

            event_id = f"TL-EVT-{idx+1:06d}"
            evt = TimelineEvent(
                event_id=event_id,
                timestamp_ms=ts,
                timestamp_utc=msg.timestamp_utc,
                event_type="MESSAGE_COMMUNICATION",
                primary_participant=msg.sender_jid or "Unknown",
                secondary_participant=msg.remote_jid,
                summary=f"{action} in {msg.remote_jid}: {text_preview}",
                associated_evidence_id=msg.message_id,
                confidence=msg.confidence,
                provenance_details=f"Source: {msg.source_file} (Record ID: {msg.message_id}, Offset: {msg.source_offset or 'Indexed'})",
                has_chronology_anomaly=has_anomaly,
                anomaly_explanation=anomaly_explanation
            )
            events.append(evt)
            prev_msg = msg

        self.events = events
        return events

    def export_csv_rows(self) -> List[Dict[str, Any]]:
        return [
            {
                "Event ID": e.event_id,
                "Timestamp UTC": e.timestamp_utc,
                "Timestamp Epoch MS": e.timestamp_ms,
                "Event Type": e.event_type,
                "Sender": e.primary_participant,
                "Recipient / Thread": e.secondary_participant,
                "Summary": e.summary,
                "Record ID": e.associated_evidence_id,
                "Confidence": e.confidence.value,
                "Provenance": e.provenance_details,
                "Anomaly Detected": "YES" if e.has_chronology_anomaly else "NO",
                "Anomaly Explanation": e.anomaly_explanation or ""
            }
            for e in self.events
        ]
