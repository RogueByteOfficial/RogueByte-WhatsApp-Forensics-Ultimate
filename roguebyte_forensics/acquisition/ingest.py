"""
RogueByte WhatsApp Forensics Ultimate - Evidence Ingestion & Cryptographic Acquisition
Author: RogueByteOfficial
"""

import os
import shutil
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple, Dict, Any

from roguebyte_forensics.core.models import EvidenceArtifact, EvidenceSourceType


# Known SQLite & WhatsApp File Signatures
SQLITE_HEADER = b"SQLite format 3\x00"
WAL_MAGIC_BE = b"\x37\x7f\x06\x82"
WAL_MAGIC_LE = b"\x37\x7f\x06\x83"
CRYPT12_MAGIC = b"\x00\x00\x00\x00"  # Typically prefixed or includes crypt headers


class EvidenceAcquisitionEngine:
    def __init__(self, case_evidence_dir: str):
        self.evidence_dir = Path(case_evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def calculate_sha256(filepath: str) -> str:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        return sha256.hexdigest()

    @staticmethod
    def identify_file_type(header_bytes: bytes, filename: str) -> Tuple[EvidenceSourceType, str]:
        fn_lower = filename.lower()
        if header_bytes.startswith(SQLITE_HEADER):
            return EvidenceSourceType.SQLITE_ACTIVE, "SQLite 3 Database"
        if header_bytes[:4] in (WAL_MAGIC_BE, WAL_MAGIC_LE) or fn_lower.endswith("-wal"):
            return EvidenceSourceType.SQLITE_WAL, "SQLite Write-Ahead Log (WAL)"
        if fn_lower.endswith("-shm"):
            return EvidenceSourceType.SQLITE_ACTIVE, "SQLite Shared Memory Index (SHM)"
        if "crypt12" in fn_lower or "crypt14" in fn_lower or "crypt15" in fn_lower:
            return EvidenceSourceType.BACKUP_CRYPT, "Encrypted WhatsApp Backup Container"
        if fn_lower.endswith(".txt") or "chat" in fn_lower:
            return EvidenceSourceType.CHAT_EXPORT, "Exported WhatsApp Text Archive"
        if any(fn_lower.endswith(ext) for ext in [".jpg", ".jpeg", ".png", ".opus", ".mp3", ".mp4", ".pdf", ".webp"]):
            return EvidenceSourceType.MEDIA_FILE, "WhatsApp Media Attachment"
        return EvidenceSourceType.SQLITE_ACTIVE, "Generic Forensic File"

    def acquire_file(self, original_path: str, evidence_id: str) -> EvidenceArtifact:
        orig = Path(original_path)
        if not orig.exists():
            raise FileNotFoundError(f"Source evidence file not found: {original_path}")

        file_size = orig.stat().st_size
        sha256_orig = self.calculate_sha256(str(orig))

        # Create working copy in evidence directory to preserve original evidence
        dest_filename = f"{evidence_id}_{orig.name}"
        dest_path = self.evidence_dir / dest_filename
        shutil.copy2(str(orig), str(dest_path))

        # Make working copy read-only on filesystem
        try:
            os.chmod(str(dest_path), 0o444)
        except Exception:
            pass

        # Verify hash of copied file
        sha256_copy = self.calculate_sha256(str(dest_path))
        if sha256_orig != sha256_copy:
            raise ValueError(f"Integrity check failed during acquisition copy: {sha256_orig} != {sha256_copy}")

        with open(dest_path, "rb") as f:
            header_sample = f.read(32)

        source_type, magic_str = self.identify_file_type(header_sample, orig.name)
        now_utc = datetime.now(timezone.utc).isoformat()

        return EvidenceArtifact(
            evidence_id=evidence_id,
            filename=orig.name,
            source_path=str(dest_path),
            file_size_bytes=file_size,
            sha256_hash=sha256_orig,
            import_timestamp_utc=now_utc,
            source_type=source_type,
            magic_bytes=header_sample[:16].hex(),
            is_read_only=True,
            metadata={
                "original_path": str(orig.absolute()),
                "format_description": magic_str,
                "verified_integrity": True
            }
        )
