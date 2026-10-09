"""
RogueByte WhatsApp Forensics Ultimate - WhatsApp Artifact Parsers
Author: RogueByteOfficial
"""

import sqlite3
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from roguebyte_forensics.core.models import (
    MessageRecord,
    MessageType,
    ConversationRecord,
    ContactRecord,
    ConfidenceCategory,
    EvidenceSourceType
)


class WhatsAppDatabaseParser:
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.warnings: List[str] = []
        self.detected_schema_version: str = "Unknown"

    def _get_connection(self) -> sqlite3.Connection:
        uri = f"file:{self.db_path.resolve()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        return conn

    def detect_schema(self, conn: sqlite3.Connection) -> str:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = set(r[0] for r in cursor.fetchall())

        if "message" in tables and "jid" in tables:
            self.detected_schema_version = "v12_v15_jid_normalized"
            return self.detected_schema_version
        elif "messages" in tables:
            self.detected_schema_version = "v1_v11_legacy_messages"
            return self.detected_schema_version
        else:
            self.detected_schema_version = "generic_or_unknown"
            self.warnings.append("Neither standard 'message' nor 'messages' table found.")
            return self.detected_schema_version

    @staticmethod
    def ms_to_utc_str(ts_ms: Optional[int]) -> str:
        if not ts_ms or ts_ms <= 0:
            return "UNKNOWN_TIMESTAMP"
        try:
            # Handle seconds vs milliseconds
            if ts_ms < 10000000000:
                ts_ms = ts_ms * 1000
            dt = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"
        except Exception:
            return f"INVALID_EPOCH({ts_ms})"

    def parse_contacts(self) -> List[ContactRecord]:
        contacts: List[ContactRecord] = []
        if not self.db_path.exists():
            return contacts

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = set(r[0] for r in cursor.fetchall())

                if "wa_contacts" in tables:
                    cursor.execute("SELECT jid, display_name, number, status FROM wa_contacts")
                    for row in cursor.fetchall():
                        jid = row["jid"] or ""
                        contacts.append(ContactRecord(
                            jid=jid,
                            display_name=row["display_name"],
                            phone_number=row["number"],
                            status=row["status"],
                            is_group="@g.us" in jid
                        ))
                elif "jid" in tables:
                    cursor.execute("SELECT _id, raw_string, user, server FROM jid")
                    for row in cursor.fetchall():
                        raw = row["raw_string"] or (f"{row['user']}@{row['server']}" if row["user"] and row["server"] else "")
                        if raw:
                            contacts.append(ContactRecord(
                                jid=raw,
                                display_name=row["user"],
                                phone_number=row["user"] if (row["user"] and row["user"].isdigit()) else None,
                                is_group="@g.us" in raw
                            ))
        except Exception as e:
            self.warnings.append(f"Contact parsing exception: {str(e)}")

        return contacts

    def parse_conversations(self) -> List[ConversationRecord]:
        conversations: List[ConversationRecord] = []
        try:
            with self._get_connection() as conn:
                schema = self.detect_schema(conn)
                cursor = conn.cursor()

                if schema == "v12_v15_jid_normalized":
                    # modern schema: chat table + jid table
                    query = """
                    SELECT 
                        c._id, 
                        j.raw_string AS chat_jid, 
                        c.subject, 
                        c.sort_timestamp,
                        (SELECT COUNT(*) FROM message WHERE chat_row_id = c._id) as msg_count
                    FROM chat c
                    LEFT JOIN jid j ON c.jid_row_id = j._id
                    ORDER BY c.sort_timestamp DESC
                    """
                    try:
                        cursor.execute(query)
                        for r in cursor.fetchall():
                            jid = r["chat_jid"] or f"chat_row_{r['_id']}"
                            is_grp = "@g.us" in jid
                            disp_name = r["subject"] or jid.split("@")[0]
                            conversations.append(ConversationRecord(
                                jid=jid,
                                display_name=disp_name,
                                is_group=is_grp,
                                total_messages=r["msg_count"] or 0,
                                active_messages=r["msg_count"] or 0,
                                last_activity_utc=self.ms_to_utc_str(r["sort_timestamp"])
                            ))
                    except Exception as e:
                        self.warnings.append(f"Error querying modern chat table: {e}")

                elif schema == "v1_v11_legacy_messages":
                    # legacy schema: chat_list or distinct key_remote_jid from messages
                    try:
                        cursor.execute("""
                            SELECT key_remote_jid, count(*) as msg_count, max(timestamp) as last_ts 
                            FROM messages 
                            WHERE key_remote_jid IS NOT NULL 
                            GROUP BY key_remote_jid
                            ORDER BY last_ts DESC
                        """)
                        for r in cursor.fetchall():
                            jid = r["key_remote_jid"]
                            is_grp = "@g.us" in jid
                            conversations.append(ConversationRecord(
                                jid=jid,
                                display_name=jid.split("@")[0],
                                is_group=is_grp,
                                total_messages=r["msg_count"],
                                active_messages=r["msg_count"],
                                last_activity_utc=self.ms_to_utc_str(r["last_ts"])
                            ))
                    except Exception as e:
                        self.warnings.append(f"Error querying legacy messages table: {e}")

        except Exception as e:
            self.warnings.append(f"Failed to extract conversations: {str(e)}")

        return conversations

    def parse_messages(self, limit: Optional[int] = None) -> List[MessageRecord]:
        messages: List[MessageRecord] = []
        try:
            with self._get_connection() as conn:
                schema = self.detect_schema(conn)
                cursor = conn.cursor()

                if schema == "v12_v15_jid_normalized":
                    query = """
                    SELECT 
                        m._id,
                        m.key_id,
                        m.from_me,
                        m.timestamp,
                        m.text_data,
                        m.message_type,
                        m.status,
                        j_chat.raw_string AS chat_jid,
                        j_sender.raw_string AS sender_jid,
                        mm.file_path,
                        mm.file_size,
                        mm.file_hash
                    FROM message m
                    LEFT JOIN chat c ON m.chat_row_id = c._id
                    LEFT JOIN jid j_chat ON c.jid_row_id = j_chat._id
                    LEFT JOIN jid j_sender ON m.sender_jid_row_id = j_sender._id
                    LEFT JOIN message_media mm ON m._id = mm.message_row_id
                    ORDER BY m.timestamp ASC
                    """
                    if limit:
                        query += f" LIMIT {limit}"

                    cursor.execute(query)
                    for r in cursor.fetchall():
                        m_type = self._map_message_type(r["message_type"])
                        status_str = self._map_status(r["status"])
                        chat_jid = r["chat_jid"] or "unknown_chat"
                        from_me = bool(r["from_me"])
                        sender = "Examiner/Account Owner" if from_me else (r["sender_jid"] or chat_jid)

                        rec = MessageRecord(
                            message_id=str(r["key_id"] or r["_id"]),
                            remote_jid=chat_jid,
                            sender_jid=sender,
                            is_from_me=from_me,
                            timestamp_ms=r["timestamp"] or 0,
                            timestamp_utc=self.ms_to_utc_str(r["timestamp"]),
                            text_content=r["text_data"],
                            message_type=m_type,
                            status=status_str,
                            media_path=r["file_path"],
                            media_sha256=r["file_hash"],
                            media_size_bytes=r["file_size"],
                            confidence=ConfidenceCategory.CONFIRMED,
                            source_type=EvidenceSourceType.SQLITE_ACTIVE,
                            source_file=self.db_path.name
                        )
                        messages.append(rec)

                elif schema == "v1_v11_legacy_messages":
                    query = """
                    SELECT 
                        _id,
                        key_id,
                        key_remote_jid,
                        key_from_me,
                        remote_resource,
                        data,
                        timestamp,
                        status,
                        media_wa_type,
                        media_size,
                        media_hash,
                        media_name
                    FROM messages
                    ORDER BY timestamp ASC
                    """
                    if limit:
                        query += f" LIMIT {limit}"

                    cursor.execute(query)
                    for r in cursor.fetchall():
                        m_type = self._map_legacy_media_type(r["media_wa_type"])
                        from_me = bool(r["key_from_me"])
                        chat_jid = r["key_remote_jid"] or "unknown_chat"
                        sender = "Examiner/Account Owner" if from_me else (r["remote_resource"] or chat_jid)

                        rec = MessageRecord(
                            message_id=str(r["key_id"] or r["_id"]),
                            remote_jid=chat_jid,
                            sender_jid=sender,
                            is_from_me=from_me,
                            timestamp_ms=r["timestamp"] or 0,
                            timestamp_utc=self.ms_to_utc_str(r["timestamp"]),
                            text_content=r["data"],
                            message_type=m_type,
                            status=str(r["status"]),
                            media_path=r["media_name"],
                            media_sha256=r["media_hash"],
                            media_size_bytes=r["media_size"],
                            confidence=ConfidenceCategory.CONFIRMED,
                            source_type=EvidenceSourceType.SQLITE_ACTIVE,
                            source_file=self.db_path.name
                        )
                        messages.append(rec)
        except Exception as e:
            self.warnings.append(f"Message parsing error: {str(e)}")

        return messages

    @staticmethod
    def _map_message_type(type_code: Optional[int]) -> MessageType:
        if type_code is None or type_code == 0:
            return MessageType.TEXT
        mapping = {
            1: MessageType.IMAGE,
            2: MessageType.AUDIO,
            3: MessageType.VIDEO,
            4: MessageType.CONTACT,
            5: MessageType.LOCATION,
            9: MessageType.DOCUMENT,
            15: MessageType.STICKER,
            8: MessageType.CALL_LOG,
            10: MessageType.REVOKED
        }
        return mapping.get(type_code, MessageType.TEXT)

    @staticmethod
    def _map_legacy_media_type(wa_type: Any) -> MessageType:
        if not wa_type or wa_type == "0":
            return MessageType.TEXT
        mapping = {
            "1": MessageType.IMAGE,
            "2": MessageType.AUDIO,
            "3": MessageType.VIDEO,
            "4": MessageType.CONTACT,
            "5": MessageType.LOCATION,
            "9": MessageType.DOCUMENT,
            "15": MessageType.STICKER
        }
        return mapping.get(str(wa_type), MessageType.TEXT)

    @staticmethod
    def _map_status(status_code: Optional[int]) -> str:
        if status_code is None:
            return "received"
        mapping = {
            0: "received",
            4: "sent",
            5: "delivered",
            13: "read",
            6: "played"
        }
        return mapping.get(status_code, f"status_{status_code}")
