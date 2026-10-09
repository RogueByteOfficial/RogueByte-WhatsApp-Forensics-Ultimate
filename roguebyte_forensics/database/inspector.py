"""
RogueByte WhatsApp Forensics Ultimate - SQLite Database & WAL Header Inspector
Author: RogueByteOfficial
"""

import struct
import sqlite3
from pathlib import Path
from typing import Dict, Any, List, Optional


class SQLiteDatabaseInspector:
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database file does not exist: {db_path}")

    def parse_header(self) -> Dict[str, Any]:
        """Parses the official 100-byte SQLite database header."""
        with open(self.db_path, "rb") as f:
            header_bytes = f.read(100)

        if len(header_bytes) < 100:
            return {"error": "File smaller than minimum SQLite 100-byte header", "valid": False}

        magic = header_bytes[:16]
        if magic != b"SQLite format 3\x00":
            return {"error": f"Invalid SQLite magic: {magic!r}", "valid": False}

        raw_page_size = struct.unpack(">H", header_bytes[16:18])[0]
        page_size = 65536 if raw_page_size == 1 else raw_page_size

        write_version, read_version = header_bytes[18], header_bytes[19]
        reserved_space = header_bytes[20]
        file_change_counter = struct.unpack(">I", header_bytes[24:28])[0]
        db_size_in_pages = struct.unpack(">I", header_bytes[28:32])[0]
        first_freelist_trunk = struct.unpack(">I", header_bytes[32:36])[0]
        total_freelist_pages = struct.unpack(">I", header_bytes[36:40])[0]
        schema_cookie = struct.unpack(">I", header_bytes[40:44])[0]
        schema_format = struct.unpack(">I", header_bytes[44:48])[0]
        encoding_code = struct.unpack(">I", header_bytes[56:60])[0]
        encoding_map = {1: "UTF-8", 2: "UTF-16le", 3: "UTF-16be"}
        text_encoding = encoding_map.get(encoding_code, f"Unknown ({encoding_code})")
        user_version = struct.unpack(">I", header_bytes[60:64])[0]
        sqlite_version_num = struct.unpack(">I", header_bytes[96:100])[0]

        calculated_file_size = self.db_path.stat().st_size
        expected_size = db_size_in_pages * page_size

        is_wal_mode = (write_version == 2 or read_version == 2)

        return {
            "valid": True,
            "page_size": page_size,
            "write_version": write_version,
            "read_version": read_version,
            "is_wal_mode": is_wal_mode,
            "reserved_space": reserved_space,
            "file_change_counter": file_change_counter,
            "db_size_in_pages": db_size_in_pages,
            "first_freelist_trunk": first_freelist_trunk,
            "total_freelist_pages": total_freelist_pages,
            "schema_cookie": schema_cookie,
            "schema_format": schema_format,
            "text_encoding": text_encoding,
            "user_version": user_version,
            "sqlite_version_num": sqlite_version_num,
            "actual_file_size": calculated_file_size,
            "expected_file_size": expected_size,
            "size_discrepancy_bytes": calculated_file_size - expected_size
        }

    def inspect_schema(self) -> Dict[str, Any]:
        """Queries database schema information using read-only URI."""
        conn = None
        try:
            # Use immutable read-only URI to ensure no modification
            uri = f"file:{self.db_path.resolve()}?mode=ro"
            conn = sqlite3.connect(uri, uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("SELECT type, name, tbl_name, rootpage, sql FROM sqlite_master ORDER BY type, name")
            rows = cursor.fetchall()

            tables = []
            indexes = []
            triggers = []
            views = []

            for r in rows:
                item = {
                    "type": r["type"],
                    "name": r["name"],
                    "table_name": r["tbl_name"],
                    "rootpage": r["rootpage"],
                    "sql": r["sql"]
                }
                if r["type"] == "table":
                    # Get table column info
                    try:
                        cursor.execute(f"PRAGMA table_info('{r['name']}')")
                        col_rows = cursor.fetchall()
                        item["columns"] = [
                            {"cid": c[0], "name": c[1], "type": c[2], "notnull": c[3], "dflt_value": c[4], "pk": c[5]}
                            for c in col_rows
                        ]
                    except Exception:
                        item["columns"] = []
                    tables.append(item)
                elif r["type"] == "index":
                    indexes.append(item)
                elif r["type"] == "trigger":
                    triggers.append(item)
                elif r["type"] == "view":
                    views.append(item)

            return {
                "tables": tables,
                "indexes": indexes,
                "triggers": triggers,
                "views": views,
                "table_count": len(tables),
                "index_count": len(indexes)
            }
        except Exception as e:
            return {"error": str(e), "tables": [], "indexes": []}
        finally:
            if conn:
                conn.close()

    def run_integrity_check(self) -> Dict[str, Any]:
        conn = None
        try:
            uri = f"file:{self.db_path.resolve()}?mode=ro"
            conn = sqlite3.connect(uri, uri=True)
            cursor = conn.cursor()

            cursor.execute("PRAGMA integrity_check(100)")
            integrity_rows = [r[0] for r in cursor.fetchall()]

            cursor.execute("PRAGMA quick_check(100)")
            quick_rows = [r[0] for r in cursor.fetchall()]

            cursor.execute("PRAGMA foreign_key_check")
            fk_rows = [list(r) for r in cursor.fetchall()]

            is_ok = (integrity_rows == ["ok"] or integrity_rows == ["OK"])

            return {
                "passed": is_ok,
                "integrity_results": integrity_rows,
                "quick_check_results": quick_rows,
                "foreign_key_violations": fk_rows,
                "violation_count": len(fk_rows)
            }
        except Exception as e:
            return {
                "passed": False,
                "error": str(e),
                "integrity_results": [f"Error executing integrity check: {e}"]
            }
        finally:
            if conn:
                conn.close()


class SQLiteWALInspector:
    """Specialized forensic inspector for SQLite Write-Ahead Log (WAL) files."""
    def __init__(self, wal_path: str):
        self.wal_path = Path(wal_path)
        if not self.wal_path.exists():
            raise FileNotFoundError(f"WAL file does not exist: {wal_path}")

    def inspect_wal(self, expected_page_size: int = 4096) -> Dict[str, Any]:
        file_size = self.wal_path.stat().st_size
        if file_size < 32:
            return {"error": "WAL file smaller than 32-byte header", "frames_count": 0}

        with open(self.wal_path, "rb") as f:
            header = f.read(32)
            magic = struct.unpack(">I", header[:4])[0]
            if magic not in (0x377f0682, 0x377f0683):
                return {"error": f"Invalid WAL magic: {hex(magic)}", "frames_count": 0}

            endianness = ">" if magic == 0x377f0682 else "<"
            format_version = struct.unpack(f"{endianness}I", header[4:8])[0]
            page_size = struct.unpack(f"{endianness}I", header[8:12])[0]
            if page_size == 0 or page_size > 65536:
                page_size = expected_page_size

            checkpoint_seq = struct.unpack(f"{endianness}I", header[12:16])[0]
            salt_1 = struct.unpack(f"{endianness}I", header[16:20])[0]
            salt_2 = struct.unpack(f"{endianness}I", header[20:24])[0]

            frame_size = 24 + page_size
            remaining_bytes = file_size - 32
            total_frames = remaining_bytes // frame_size

            frames = []
            modified_pages = set()
            commit_frames = 0

            # Inspect frames
            for i in range(total_frames):
                frame_offset = 32 + (i * frame_size)
                f.seek(frame_offset)
                frame_header = f.read(24)
                if len(frame_header) < 24:
                    break

                page_num = struct.unpack(f"{endianness}I", frame_header[:4])[0]
                db_size_commit = struct.unpack(f"{endianness}I", frame_header[4:8])[0]
                frame_salt1 = struct.unpack(f"{endianness}I", frame_header[8:12])[0]
                frame_salt2 = struct.unpack(f"{endianness}I", frame_header[12:16])[0]

                is_commit = (db_size_commit > 0)
                if is_commit:
                    commit_frames += 1
                modified_pages.add(page_num)

                salt_valid = (frame_salt1 == salt_1 and frame_salt2 == salt_2)

                frames.append({
                    "frame_index": i + 1,
                    "offset": frame_offset,
                    "page_number": page_num,
                    "is_commit": is_commit,
                    "commit_db_size_pages": db_size_commit,
                    "salt_match": salt_valid
                })

            return {
                "valid_wal": True,
                "magic": hex(magic),
                "format_version": format_version,
                "page_size": page_size,
                "checkpoint_seq": checkpoint_seq,
                "salt": f"{hex(salt_1)}:{hex(salt_2)}",
                "total_frames": total_frames,
                "commit_frames": commit_frames,
                "unique_pages_modified": len(modified_pages),
                "modified_page_numbers": sorted(list(modified_pages)),
                "frames": frames[:50]  # First 50 for summary
            }
