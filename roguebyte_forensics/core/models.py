"""
RogueByte WhatsApp Forensics Ultimate - Core Models & Data Structures
Author: RogueByteOfficial
License: Proprietary / Educational & Lawful Digital Forensics
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone


class ConfidenceCategory(str, Enum):
    """
    Forensic confidence classification for recovered records.
    Strictly defined by RogueByte forensic standard to avoid misleading claims.
    """
    CONFIRMED = "CONFIRMED"          # Structurally validated record with intact fields & primary keys
    PARTIAL = "PARTIAL"              # Fragmentary record with readable text but missing relational IDs
    INFERRED = "INFERRED"            # Analytical deduction based on surrounding references/metadata
    UNVERIFIED = "UNVERIFIED"        # Raw unallocated carver hit lacking relational validation
    UNRECOVERABLE = "UNRECOVERABLE"  # Overwritten or corrupted beyond reliable forensic recovery


class EvidenceSourceType(str, Enum):
    SQLITE_ACTIVE = "SQLITE_ACTIVE"
    SQLITE_WAL = "SQLITE_WAL"
    SQLITE_JOURNAL = "SQLITE_JOURNAL"
    UNALLOCATED_PAGE = "UNALLOCATED_PAGE"
    FREELIST_BLOCK = "FREELIST_BLOCK"
    BACKUP_CRYPT = "BACKUP_CRYPT"
    CHAT_EXPORT = "CHAT_EXPORT"
    MEDIA_FILE = "MEDIA_FILE"


class MessageType(str, Enum):
    TEXT = "text"
    IMAGE = "image"
    AUDIO = "audio"
    VIDEO = "video"
    DOCUMENT = "document"
    STICKER = "sticker"
    LOCATION = "location"
    CONTACT = "contact"
    CALL_LOG = "call"
    REVOKED = "revoked"
    SYSTEM = "system"


@dataclass
class EvidenceArtifact:
    evidence_id: str
    filename: str
    source_path: str
    file_size_bytes: int
    sha256_hash: str
    import_timestamp_utc: str
    source_type: EvidenceSourceType
    magic_bytes: str
    is_read_only: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MessageRecord:
    message_id: str
    remote_jid: str
    sender_jid: Optional[str] = None
    sender_name: Optional[str] = None
    is_from_me: bool = False
    timestamp_ms: int = 0
    timestamp_utc: str = ""
    text_content: Optional[str] = None
    message_type: MessageType = MessageType.TEXT
    status: str = "received"          # received, sent, delivered, read
    media_url: Optional[str] = None
    media_path: Optional[str] = None
    media_sha256: Optional[str] = None
    media_size_bytes: Optional[int] = None
    media_duration_seconds: Optional[int] = None
    quoted_message_id: Optional[str] = None
    confidence: ConfidenceCategory = ConfidenceCategory.CONFIRMED
    source_type: EvidenceSourceType = EvidenceSourceType.SQLITE_ACTIVE
    source_offset: Optional[int] = None
    source_file: str = ""
    is_deleted: bool = False
    recovery_method: Optional[str] = None
    notes: Optional[str] = None


@dataclass
class ContactRecord:
    jid: str
    display_name: Optional[str] = None
    phone_number: Optional[str] = None
    status: Optional[str] = None
    is_group: bool = False
    message_count: int = 0
    first_seen_utc: Optional[str] = None
    last_seen_utc: Optional[str] = None


@dataclass
class ConversationRecord:
    jid: str
    display_name: str
    is_group: bool
    total_messages: int = 0
    active_messages: int = 0
    deleted_recovered_messages: int = 0
    last_activity_utc: Optional[str] = None
    participants: List[str] = field(default_factory=list)


@dataclass
class TimelineEvent:
    event_id: str
    timestamp_ms: int
    timestamp_utc: str
    event_type: str                   # message_sent, message_received, call, media_download, etc.
    primary_participant: str
    secondary_participant: Optional[str]
    summary: str
    associated_evidence_id: str
    confidence: ConfidenceCategory
    provenance_details: str
    has_chronology_anomaly: bool = False
    anomaly_explanation: Optional[str] = None


@dataclass
class DeletedCandidate:
    candidate_id: str
    source_file: str
    byte_offset: int
    raw_payload_hex: str
    decoded_text: Optional[str]
    confidence: ConfidenceCategory
    recovery_mechanism: str          # "WAL_FRAME_SCAN", "UNALLOCATED_CARVE", "FREELIST_SCAN"
    structural_validation_pass: bool
    field_integrity: Dict[str, bool]
    examiner_rationale: str


@dataclass
class AuditLogEntry:
    entry_id: str
    timestamp_utc: str
    action_type: str
    target_evidence_id: Optional[str]
    details: str
    examiner_id: str
    sha256_verification_status: str
