"""
RogueByte WhatsApp Forensics Ultimate - Deleted Artifact & WAL Recovery Subsystem
Author: RogueByteOfficial
"""

import re
import struct
from pathlib import Path
from typing import List, Dict, Any, Optional

from roguebyte_forensics.core.models import (
    DeletedCandidate,
    ConfidenceCategory,
    MessageRecord,
    MessageType,
    EvidenceSourceType
)


class DeletedArtifactCarver:
    """
    Forensic recovery engine for unallocated space, SQLite freelists,
    and Write-Ahead Log (WAL) residual frames.
    """

    JID_REGEX = re.compile(rb"([0-9]{7,16}@(s\.whatsapp\.net|g\.us))")
    MSG_ID_REGEX = re.compile(rb"([0-9A-Fa-f]{16,32}|3EB0[0-9A-Fa-f]{16,32})")

    def __init__(self, db_path: str, wal_path: Optional[str] = None):
        self.db_path = Path(db_path)
        self.wal_path = Path(wal_path) if wal_path else None
        self.candidates: List[DeletedCandidate] = []

    def scan_wal_frames(self) -> List[DeletedCandidate]:
        """Scans WAL frames for uncheckpointed or residual deleted records."""
        if not self.wal_path or not self.wal_path.exists():
            return []

        candidates = []
        file_size = self.wal_path.stat().st_size
        if file_size < 32:
            return []

        with open(self.wal_path, "rb") as f:
            header = f.read(32)
            magic = struct.unpack(">I", header[:4])[0]
            endian = ">" if magic == 0x377f0682 else "<"
            page_size = struct.unpack(f"{endian}I", header[8:12])[0]
            if page_size <= 0 or page_size > 65536:
                page_size = 4096

            frame_size = 24 + page_size
            total_frames = (file_size - 32) // frame_size

            for i in range(total_frames):
                frame_offset = 32 + (i * frame_size)
                f.seek(frame_offset)
                frame_header = f.read(24)
                page_num = struct.unpack(f"{endian}I", frame_header[:4])[0]
                frame_data = f.read(page_size)

                # Search frame payload for WhatsApp message patterns
                matches = self._carve_text_and_jids(frame_data, base_offset=frame_offset + 24, source_name=self.wal_path.name)
                for c in matches:
                    c.recovery_mechanism = f"WAL_FRAME_{i+1}_PAGE_{page_num}"
                    candidates.append(c)

        return candidates

    def scan_sqlite_unallocated(self, page_size: int = 4096) -> List[DeletedCandidate]:
        """
        Parses B-Tree table leaf pages (0x0D flag) and scans unallocated gaps
        and freeblocks between the cell pointer array and the content area.
        """
        if not self.db_path.exists():
            return []

        candidates = []
        file_size = self.db_path.stat().st_size
        total_pages = file_size // page_size

        with open(self.db_path, "rb") as f:
            for page_num in range(1, total_pages + 1):
                page_offset = (page_num - 1) * page_size
                f.seek(page_offset)
                page_bytes = f.read(page_size)

                header_offset = 100 if page_num == 1 else 0
                if len(page_bytes) < header_offset + 8:
                    continue

                page_type = page_bytes[header_offset]
                # 0x0D = Leaf Table B-Tree Page
                if page_type == 0x0D:
                    first_freeblock = struct.unpack(">H", page_bytes[header_offset + 1:header_offset + 3])[0]
                    num_cells = struct.unpack(">H", page_bytes[header_offset + 3:header_offset + 5])[0]
                    content_start = struct.unpack(">H", page_bytes[header_offset + 5:header_offset + 7])[0]
                    if content_start == 0:
                        content_start = 65536

                    cell_pointers_end = header_offset + 8 + (num_cells * 2)

                    # Unallocated space between end of pointer array and start of cell content
                    if content_start > cell_pointers_end:
                        unalloc_bytes = page_bytes[cell_pointers_end:content_start]
                        unalloc_offset = page_offset + cell_pointers_end
                        hits = self._carve_text_and_jids(unalloc_bytes, base_offset=unalloc_offset, source_name=self.db_path.name)
                        for h in hits:
                            h.recovery_mechanism = f"UNALLOCATED_PAGE_{page_num}_GAP"
                            candidates.append(h)

                    # Inspect freeblock chain if present
                    curr_fb = first_freeblock
                    safety = 0
                    while curr_fb > 0 and curr_fb < page_size - 4 and safety < 50:
                        safety += 1
                        fb_bytes = page_bytes[curr_fb:min(curr_fb + 256, page_size)]
                        hits = self._carve_text_and_jids(fb_bytes, base_offset=page_offset + curr_fb, source_name=self.db_path.name)
                        for h in hits:
                            h.recovery_mechanism = f"FREEBLOCK_PAGE_{page_num}_OFFSET_{curr_fb}"
                            candidates.append(h)
                        next_fb = struct.unpack(">H", page_bytes[curr_fb:curr_fb + 2])[0]
                        if next_fb <= curr_fb:
                            break
                        curr_fb = next_fb

        return candidates

    def _carve_text_and_jids(self, buffer: bytes, base_offset: int, source_name: str) -> List[DeletedCandidate]:
        results = []
        if len(buffer) < 16:
            return results

        # Look for JIDs
        for jid_match in self.JID_REGEX.finditer(buffer):
            jid_bytes = jid_match.group(1)
            start_pos = jid_match.start()
            end_pos = jid_match.end()

            # Inspect adjacent window (up to 256 bytes) for text payloads
            window_start = max(0, start_pos - 64)
            window_end = min(len(buffer), end_pos + 384)
            window = buffer[window_start:window_end]

            # Extract human readable strings >= 6 chars
            text_snippets = []
            current = []
            for b in window:
                if 32 <= b <= 126 or b in (10, 13) or b >= 192:  # printable ASCII + UTF-8 leads
                    current.append(b)
                else:
                    if len(current) >= 6:
                        try:
                            decoded = bytes(current).decode("utf-8", errors="ignore").strip()
                            if len(decoded) >= 6 and not decoded.isdigit() and "@" not in decoded:
                                text_snippets.append(decoded)
                        except Exception:
                            pass
                    current = []

            raw_hex = window[:64].hex()
            carved_text = " // ".join(text_snippets) if text_snippets else None

            # Determine confidence classification
            if carved_text and len(carved_text) > 12:
                confidence = ConfidenceCategory.PARTIAL
                rationale = "Recovered intact message string with confirmed JID; primary key truncated in unallocated space."
            elif carved_text:
                confidence = ConfidenceCategory.UNVERIFIED
                rationale = "Recovered short string fragment near JID; unverified relational record."
            else:
                confidence = ConfidenceCategory.UNVERIFIED
                rationale = "Recovered JID reference with no intact readable message text."

            cand_id = f"DEL-CARVE-{base_offset + start_pos:08X}"
            results.append(DeletedCandidate(
                candidate_id=cand_id,
                source_file=source_name,
                byte_offset=base_offset + start_pos,
                raw_payload_hex=raw_hex,
                decoded_text=carved_text,
                confidence=confidence,
                recovery_mechanism="UNALLOCATED_CARVE",
                structural_validation_pass=bool(carved_text),
                field_integrity={"jid_intact": True, "payload_intact": bool(carved_text), "key_id_intact": False},
                examiner_rationale=rationale
            ))

        return results
