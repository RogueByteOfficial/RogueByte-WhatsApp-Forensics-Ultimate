"""
RogueByte WhatsApp Forensics Ultimate - Cryptographic Integrity & Audit Logging
Author: RogueByteOfficial
"""

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from roguebyte_forensics.core.models import AuditLogEntry, EvidenceArtifact


class ChainOfCustodyAuditManager:
    def __init__(self, audit_log_path: str):
        self.log_path = Path(audit_log_path)
        self.entries: List[AuditLogEntry] = []
        if self.log_path.exists():
            self._load()

    def _load(self):
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data:
                    self.entries.append(AuditLogEntry(**item))
        except Exception:
            self.entries = []

    def record_action(
        self,
        action_type: str,
        details: str,
        examiner_id: str,
        target_evidence_id: Optional[str] = None,
        sha256_verification_status: str = "VERIFIED_MATCH"
    ) -> AuditLogEntry:
        now_utc = datetime.now(timezone.utc).isoformat()
        entry_id = f"AUD-{len(self.entries) + 1:05d}"
        entry = AuditLogEntry(
            entry_id=entry_id,
            timestamp_utc=now_utc,
            action_type=action_type,
            target_evidence_id=target_evidence_id,
            details=details,
            examiner_id=examiner_id,
            sha256_verification_status=sha256_verification_status
        )
        self.entries.append(entry)
        self._flush()
        return entry

    def _flush(self):
        with open(self.log_path, "w", encoding="utf-8") as f:
            json.dump([e.__dict__ for e in self.entries], f, indent=2)

    def verify_artifact_hash(self, artifact: EvidenceArtifact) -> Dict[str, Any]:
        """Recalculates file hash and compares against acquisition record."""
        current_sha256 = hashlib.sha256()
        with open(artifact.source_path, "rb") as f:
            while chunk := f.read(65536):
                current_sha256.update(chunk)
        calc = current_sha256.hexdigest()

        is_match = (calc.lower() == artifact.sha256_hash.lower())
        status = "VERIFIED_INTACT" if is_match else "HASH_MISMATCH_TAMPERED"

        return {
            "evidence_id": artifact.evidence_id,
            "filename": artifact.filename,
            "recorded_sha256": artifact.sha256_hash,
            "current_sha256": calc,
            "is_valid": is_match,
            "status": status,
            "timestamp_utc": datetime.now(timezone.utc).isoformat()
        }

    def generate_evidence_manifest(self, artifacts: List[EvidenceArtifact], case_id: str, examiner_id: str) -> Dict[str, Any]:
        return {
            "case_id": case_id,
            "examiner_id": examiner_id,
            "manifest_generated_utc": datetime.now(timezone.utc).isoformat(),
            "forensics_tool": "RogueByte WhatsApp Forensics Ultimate v2.5",
            "artifact_count": len(artifacts),
            "artifacts": [
                {
                    "evidence_id": a.evidence_id,
                    "filename": a.filename,
                    "sha256": a.sha256_hash,
                    "size_bytes": a.file_size_bytes,
                    "source_type": a.source_type.value,
                    "magic_bytes": a.magic_bytes
                }
                for a in artifacts
            ],
            "audit_entries_count": len(self.entries)
        }
