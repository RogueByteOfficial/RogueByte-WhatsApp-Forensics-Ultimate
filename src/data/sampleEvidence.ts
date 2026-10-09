/**
 * RogueByte WhatsApp Forensics Ultimate - Realistic Authorized Case Data
 * Case Reference: RB-2026-089
 * Matter: Corporate Intellectual Property Exfiltration Investigation
 * Authorization: District Court Search Warrant Order #SW-2026-9041A
 */

import {
  CaseMetadata,
  EvidenceArtifact,
  MessageRecord,
  ConversationRecord,
  ContactRecord,
  DeletedCandidate,
  TimelineEvent,
  AuditLogEntry
} from '../types/forensics';

export const INITIAL_CASE_METADATA: CaseMetadata = {
  caseId: 'RB-2026-089',
  caseTitle: 'Matter of Apex Propulsion IP Leak - Forensic Device T-04',
  examinerName: 'Agent Marcus Vance, CCE, GCFE',
  examinerId: 'EX-9482',
  agencyName: 'Cyber Incident Response & Digital Forensics Laboratory (CIR-DFIR)',
  authorizationReference: 'Judicial Warrant #SW-2026-9041A (Authorized Mobile Acquisition)',
  creationTimestampUtc: '2026-03-14 09:20:15.000 UTC',
  lastModifiedUtc: '2026-03-14 14:45:00.000 UTC',
  notes: 'Logical and physical extraction of suspect Android device Samsung Galaxy S23 (SM-S911B). WhatsApp database msgstore.db, accompanying WAL file, and decrypted database copy acquired under strict write-blocking controls.'
};

export const SAMPLE_ARTIFACTS: EvidenceArtifact[] = [
  {
    evidenceId: 'EVID-001-MSGSTORE',
    filename: 'msgstore.db',
    fileSizeBytes: 2457600,
    sha256Hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    importTimestampUtc: '2026-03-14 09:32:10.120 UTC',
    sourceType: 'SQLITE_ACTIVE',
    magicBytes: '53514c69746520666f726d6174203300',
    isReadOnly: true,
    devicePlatform: 'Android',
    schemaVersion: 'WhatsApp v2.24.8.85 (Schema v15 / JID Normalized)',
    notes: 'Primary SQLite messages database located at /data/data/com.whatsapp/databases/msgstore.db'
  },
  {
    evidenceId: 'EVID-002-WAL',
    filename: 'msgstore.db-wal',
    fileSizeBytes: 524288,
    sha256Hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    importTimestampUtc: '2026-03-14 09:32:11.450 UTC',
    sourceType: 'SQLITE_WAL',
    magicBytes: '377f0682002de9840000100000000001',
    isReadOnly: true,
    devicePlatform: 'Android',
    schemaVersion: 'SQLite 3.39+ WAL Format (32-byte header + 128 frames)',
    notes: 'Write-Ahead Log capturing uncheckpointed transactions and purged record remnants'
  },
  {
    evidenceId: 'EVID-003-WADB',
    filename: 'wa.db',
    fileSizeBytes: 393216,
    sha256Hash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    importTimestampUtc: '2026-03-14 09:33:05.800 UTC',
    sourceType: 'SQLITE_ACTIVE',
    magicBytes: '53514c69746520666f726d6174203300',
    isReadOnly: true,
    devicePlatform: 'Android',
    schemaVersion: 'WhatsApp Contacts Database (wa_contacts table)',
    notes: 'Contacts address book database containing synced phonebook identities and JIDs'
  },
  {
    evidenceId: 'EVID-004-CRYPT15',
    filename: 'msgstore.db.crypt15',
    fileSizeBytes: 1843200,
    sha256Hash: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    importTimestampUtc: '2026-03-14 09:35:22.010 UTC',
    sourceType: 'BACKUP_CRYPT',
    magicBytes: '0000000077612d637279707431350000',
    isReadOnly: true,
    devicePlatform: 'Android',
    schemaVersion: 'WhatsApp Encrypted Backup Format v15 (AES-256-GCM / PBKDF2 salt extracted)',
    notes: 'External storage backup acquired from /sdcard/WhatsApp/Databases/'
  },
  {
    evidenceId: 'EVID-005-MEDIA-ZIP',
    filename: 'WhatsApp_Media_Evidence.zip',
    fileSizeBytes: 14680064,
    sha256Hash: 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
    importTimestampUtc: '2026-03-14 09:40:00.000 UTC',
    sourceType: 'MEDIA_FILE',
    magicBytes: '504b0304140008000800000000000000',
    isReadOnly: true,
    devicePlatform: 'Android',
    schemaVersion: 'Correlated Media Directory (/WhatsApp/Media/WhatsApp Images & Documents)',
    notes: 'Cryptographically hashed media archive containing correlated images, voice notes, and PDF blueprints'
  }
];

export const SAMPLE_CONTACTS: ContactRecord[] = [
  {
    jid: '14155550192@s.whatsapp.net',
    displayName: 'Dr. Gregory Finch',
    phoneNumber: '+1 (415) 555-0192',
    status: 'Busy at propulsion labs',
    isGroup: false,
    messageCount: 38
  },
  {
    jid: '12065550843@s.whatsapp.net',
    displayName: 'Elena Rostova (Apex Competitor)',
    phoneNumber: '+1 (206) 555-0843',
    status: 'Available on Signal / Telegram',
    isGroup: false,
    messageCount: 19
  },
  {
    jid: '14155550999@s.whatsapp.net',
    displayName: 'David Miller (Chief Legal Officer)',
    phoneNumber: '+1 (415) 555-0999',
    status: 'Legal review in progress',
    isGroup: false,
    messageCount: 12
  },
  {
    jid: '12036304918239101@g.us',
    displayName: 'Project Apex Falcon Core Engineering',
    phoneNumber: undefined,
    status: 'Confidential Internal Working Group',
    isGroup: true,
    messageCount: 54
  },
  {
    jid: '12036319847120934@g.us',
    displayName: 'Off-Grid Offshore Transfer',
    phoneNumber: undefined,
    status: 'Ephemeral Group (Disbanded)',
    isGroup: true,
    messageCount: 8
  }
];

export const SAMPLE_CONVERSATIONS: ConversationRecord[] = [
  {
    jid: '12065550843@s.whatsapp.net',
    displayName: 'Elena Rostova (Apex Competitor)',
    isGroup: false,
    totalMessages: 19,
    activeMessages: 13,
    deletedRecoveredMessages: 6,
    lastActivityUtc: '2026-03-13 23:48:12.440 UTC',
    participants: ['12065550843@s.whatsapp.net', 'Examiner/Account Owner']
  },
  {
    jid: '12036304918239101@g.us',
    displayName: 'Project Apex Falcon Core Engineering',
    isGroup: true,
    totalMessages: 54,
    activeMessages: 54,
    deletedRecoveredMessages: 0,
    lastActivityUtc: '2026-03-13 18:22:00.110 UTC',
    participants: ['14155550192@s.whatsapp.net', '14155550999@s.whatsapp.net', 'Examiner/Account Owner']
  },
  {
    jid: '12036319847120934@g.us',
    displayName: 'Off-Grid Offshore Transfer',
    isGroup: true,
    totalMessages: 8,
    activeMessages: 2,
    deletedRecoveredMessages: 6,
    lastActivityUtc: '2026-03-13 22:15:33.000 UTC',
    participants: ['12065550843@s.whatsapp.net', '14155550192@s.whatsapp.net', 'Examiner/Account Owner']
  },
  {
    jid: '14155550192@s.whatsapp.net',
    displayName: 'Dr. Gregory Finch',
    isGroup: false,
    totalMessages: 38,
    activeMessages: 38,
    deletedRecoveredMessages: 0,
    lastActivityUtc: '2026-03-13 16:40:19.000 UTC',
    participants: ['14155550192@s.whatsapp.net', 'Examiner/Account Owner']
  }
];

export const SAMPLE_MESSAGES: MessageRecord[] = [
  {
    messageId: '3EB07A1992F01AA44B8C',
    remoteJid: '12065550843@s.whatsapp.net',
    senderJid: '12065550843@s.whatsapp.net',
    senderName: 'Elena Rostova',
    isFromMe: false,
    timestampMs: 1773440400000,
    timestampUtc: '2026-03-13 22:20:00.000 UTC',
    textContent: 'Are you prepared to provide the telemetry schemas for the Falcon Mach-4 turbine stage?',
    messageType: 'text',
    status: 'read',
    confidence: 'CONFIRMED',
    sourceType: 'SQLITE_ACTIVE',
    sourceOffset: 147456,
    sourceFile: 'msgstore.db',
    isDeleted: false
  },
  {
    messageId: '3EB0891C837EA01129DF',
    remoteJid: '12065550843@s.whatsapp.net',
    senderJid: 'Examiner/Account Owner',
    senderName: 'Device Owner (Subject)',
    isFromMe: true,
    timestampMs: 1773440520000,
    timestampUtc: '2026-03-13 22:22:00.000 UTC',
    textContent: 'I extracted the CAD models and materials stress tables from the vault this afternoon.',
    messageType: 'text',
    status: 'read',
    confidence: 'CONFIRMED',
    sourceType: 'SQLITE_ACTIVE',
    sourceOffset: 147812,
    sourceFile: 'msgstore.db',
    isDeleted: false
  },
  {
    messageId: '3EB0901FA87BC42031EE',
    remoteJid: '12065550843@s.whatsapp.net',
    senderJid: 'Examiner/Account Owner',
    senderName: 'Device Owner (Subject)',
    isFromMe: true,
    timestampMs: 1773440640000,
    timestampUtc: '2026-03-13 22:24:00.000 UTC',
    textContent: 'Sending the encrypted PDF blueprint now. Make sure you delete the chat history immediately.',
    messageType: 'document',
    status: 'read',
    mediaPath: '/WhatsApp/Media/WhatsApp Documents/Apex_Falcon_Turbine_Schematic_v4.pdf',
    mediaSha256: 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0',
    mediaSizeBytes: 4892140,
    confidence: 'CONFIRMED',
    sourceType: 'SQLITE_ACTIVE',
    sourceOffset: 148190,
    sourceFile: 'msgstore.db',
    isDeleted: false
  },
  {
    messageId: '3EB0AA4182910FF49821',
    remoteJid: '12065550843@s.whatsapp.net',
    senderJid: '12065550843@s.whatsapp.net',
    senderName: 'Elena Rostova',
    isFromMe: false,
    timestampMs: 1773440800000,
    timestampUtc: '2026-03-13 22:26:40.000 UTC',
    textContent: 'Blueprint received and checksum verified. Wire transfer to Zurich account confirmed.',
    messageType: 'text',
    status: 'read',
    confidence: 'CONFIRMED',
    sourceType: 'SQLITE_ACTIVE',
    sourceOffset: 148920,
    sourceFile: 'msgstore.db',
    isDeleted: false
  },
  // Deleted Records Recovered from WAL Frames & Freelist Unallocated Space
  {
    messageId: 'DEL-WAL-0048-REC01',
    remoteJid: '12065550843@s.whatsapp.net',
    senderJid: 'Examiner/Account Owner',
    senderName: 'Device Owner (Subject)',
    isFromMe: true,
    timestampMs: 1773441000000,
    timestampUtc: '2026-03-13 22:30:00.000 UTC',
    textContent: 'PURGED BY USER: I am deleting our chat and wiping the SD cache now. See you in Geneva.',
    messageType: 'text',
    status: 'read',
    confidence: 'CONFIRMED',
    sourceType: 'SQLITE_WAL',
    sourceOffset: 201728, // Offset within msgstore.db-wal
    sourceFile: 'msgstore.db-wal',
    isDeleted: true,
    recoveryMethod: 'WAL_FRAME_48_RECONSTRUCTION',
    notes: 'Record purged from active message table. Intact B-tree row payload discovered in WAL Frame #48 before checkpoint commit.'
  },
  {
    messageId: 'DEL-WAL-0049-REC02',
    remoteJid: '12065550843@s.whatsapp.net',
    senderJid: '12065550843@s.whatsapp.net',
    senderName: 'Elena Rostova',
    isFromMe: false,
    timestampMs: 1773441120000,
    timestampUtc: '2026-03-13 22:32:00.000 UTC',
    textContent: 'DELETED: Confirmation code for the vault deposit box is 9942-ALPHA-Z.',
    messageType: 'text',
    status: 'read',
    confidence: 'CONFIRMED',
    sourceType: 'SQLITE_WAL',
    sourceOffset: 205824,
    sourceFile: 'msgstore.db-wal',
    isDeleted: true,
    recoveryMethod: 'WAL_FRAME_49_RECONSTRUCTION',
    notes: 'Fully reconstructed record from WAL Frame #49. Primary key and JID serial headers fully valid.'
  },
  {
    messageId: 'DEL-SLACK-0021-CARV',
    remoteJid: '12036319847120934@g.us',
    senderJid: '12065550843@s.whatsapp.net',
    senderName: 'Elena Rostova',
    isFromMe: false,
    timestampMs: 1773442000000,
    timestampUtc: '2026-03-13 22:46:40.000 UTC',
    textContent: 'SLACK CARVE: Transfer batch 3 initiated... [fragmentary record]',
    messageType: 'text',
    status: 'received',
    confidence: 'PARTIAL',
    sourceType: 'UNALLOCATED_PAGE',
    sourceOffset: 348160,
    sourceFile: 'msgstore.db',
    isDeleted: true,
    recoveryMethod: 'SQLITE_LEAF_PAGE_SLACK_CARVER',
    notes: 'Carved from unallocated gap in B-tree leaf page 85. Text payload intact, but row ID header truncated.'
  },
  {
    messageId: '3EB09918204918290123',
    remoteJid: '12036304918239101@g.us',
    senderJid: '14155550192@s.whatsapp.net',
    senderName: 'Dr. Gregory Finch',
    isFromMe: false,
    timestampMs: 1773426000000,
    timestampUtc: '2026-03-13 18:20:00.000 UTC',
    textContent: 'Team, please review the latest stress report before the board meeting tomorrow.',
    messageType: 'text',
    status: 'received',
    confidence: 'CONFIRMED',
    sourceType: 'SQLITE_ACTIVE',
    sourceOffset: 98304,
    sourceFile: 'msgstore.db',
    isDeleted: false
  },
  // Intentional Chronological Anomaly for Forensic Detection (Future Timestamp / Clock Skew)
  {
    messageId: '3EB09999999999999999',
    remoteJid: '14155550192@s.whatsapp.net',
    senderJid: 'Examiner/Account Owner',
    senderName: 'Device Owner (Subject)',
    isFromMe: true,
    timestampMs: 2060000000000, // Year 2035!
    timestampUtc: '2035-04-12 11:33:20.000 UTC',
    textContent: 'Meeting notes draft scheduled for sync.',
    messageType: 'text',
    status: 'sent',
    confidence: 'CONFIRMED',
    sourceType: 'SQLITE_ACTIVE',
    sourceOffset: 122880,
    sourceFile: 'msgstore.db',
    isDeleted: false,
    notes: 'FLAGGED ANOMALY: Timestamp is 9+ years in future relative to acquisition date.'
  }
];

export const SAMPLE_DELETED_CANDIDATES: DeletedCandidate[] = [
  {
    candidateId: 'DEL-WAL-0048-REC01',
    sourceFile: 'msgstore.db-wal',
    byteOffset: 201728,
    rawPayloadHex: '07153EB044454C303031204920616d2064656c6574696e67206f7572206368617420616e6420776970696e6720746865205344206361636865206e6f772e',
    decodedText: 'PURGED BY USER: I am deleting our chat and wiping the SD cache now. See you in Geneva.',
    confidence: 'CONFIRMED',
    recoveryMechanism: 'WAL_FRAME_48_RECONSTRUCTION',
    structuralValidationPass: true,
    fieldIntegrity: {
      jidIntact: true,
      payloadIntact: true,
      keyIdIntact: true
    },
    examinerRationale: 'Structurally intact SQLite cell payload preserved in WAL frame before checkpoint flush. Matching remote JID and timestamp serials confirmed.'
  },
  {
    candidateId: 'DEL-WAL-0049-REC02',
    sourceFile: 'msgstore.db-wal',
    byteOffset: 205824,
    rawPayloadHex: '07183EB044454C303032436f6e6669726d6174696f6e20636f646520666f7220746865207661756c74206465706f73697420626f7820697320393934322d',
    decodedText: 'DELETED: Confirmation code for the vault deposit box is 9942-ALPHA-Z.',
    confidence: 'CONFIRMED',
    recoveryMechanism: 'WAL_FRAME_49_RECONSTRUCTION',
    structuralValidationPass: true,
    fieldIntegrity: {
      jidIntact: true,
      payloadIntact: true,
      keyIdIntact: true
    },
    examinerRationale: 'Complete record carved from WAL Frame #49 with valid varint serial lengths and primary key row correlation.'
  },
  {
    candidateId: 'DEL-SLACK-0021-CARV',
    sourceFile: 'msgstore.db',
    byteOffset: 348160,
    rawPayloadHex: '5472616e73666572206261746368203320696e697469617465642e2e2e20313230363535353038343340732e77686174736170702e6e6574',
    decodedText: 'Transfer batch 3 initiated... [Target: 12065550843@s.whatsapp.net]',
    confidence: 'PARTIAL',
    recoveryMechanism: 'SQLITE_LEAF_PAGE_SLACK_CARVER',
    structuralValidationPass: false,
    fieldIntegrity: {
      jidIntact: true,
      payloadIntact: true,
      keyIdIntact: false
    },
    examinerRationale: 'UTF-8 string fragment recovered from unallocated slack space on Page #85. Corroborated by intact JID string; row ID header was partially overwritten.'
  },
  {
    candidateId: 'DEL-FREE-0012-FRAG',
    sourceFile: 'msgstore.db',
    byteOffset: 412800,
    rawPayloadHex: '617574685f746f6b656e5f73657373696f6e5f393832313437',
    decodedText: 'auth_token_session_982147',
    confidence: 'UNVERIFIED',
    recoveryMechanism: 'FREELIST_TRUNK_SCAN',
    structuralValidationPass: false,
    fieldIntegrity: {
      jidIntact: false,
      payloadIntact: true,
      keyIdIntact: false
    },
    examinerRationale: 'Residual session token string carved from freelist page. Lacks relational metadata linking to specific conversation thread.'
  },
  {
    candidateId: 'DEL-PURGE-0099-LOST',
    sourceFile: 'msgstore.db',
    byteOffset: 524288,
    rawPayloadHex: '0000000000000000000000000000000000000000000000000000000000000000',
    decodedText: null,
    confidence: 'UNRECOVERABLE',
    recoveryMechanism: 'ZEROED_BLOCK_INSPECTION',
    structuralValidationPass: false,
    fieldIntegrity: {
      jidIntact: false,
      payloadIntact: false,
      keyIdIntact: false
    },
    examinerRationale: 'Zeroed page sector resulting from SQLite secure_delete overwrite or file compaction. Payload is mathematically unrecoverable from this location.'
  }
];

export const SAMPLE_TIMELINE_EVENTS: TimelineEvent[] = [
  {
    eventId: 'TL-EVT-0001',
    timestampMs: 1773426000000,
    timestampUtc: '2026-03-13 18:20:00.000 UTC',
    eventType: 'GROUP_MESSAGE',
    primaryParticipant: '14155550192@s.whatsapp.net',
    secondaryParticipant: '12036304918239101@g.us',
    summary: 'Dr. Gregory Finch posted in Project Apex Falcon Core Engineering: "Team, please review the latest stress report..."',
    associatedEvidenceId: '3EB09918204918290123',
    confidence: 'CONFIRMED',
    provenanceDetails: 'Source: msgstore.db (Row ID #142, Offset: 0x00018000)',
    hasChronologyAnomaly: false
  },
  {
    eventId: 'TL-EVT-0002',
    timestampMs: 1773440400000,
    timestampUtc: '2026-03-13 22:20:00.000 UTC',
    eventType: 'DIRECT_MESSAGE_INBOUND',
    primaryParticipant: '12065550843@s.whatsapp.net',
    secondaryParticipant: 'Examiner/Account Owner',
    summary: 'Elena Rostova: "Are you prepared to provide the telemetry schemas for the Falcon Mach-4 turbine stage?"',
    associatedEvidenceId: '3EB07A1992F01AA44B8C',
    confidence: 'CONFIRMED',
    provenanceDetails: 'Source: msgstore.db (Row ID #189, Offset: 0x00024000)',
    hasChronologyAnomaly: false
  },
  {
    eventId: 'TL-EVT-0003',
    timestampMs: 1773440520000,
    timestampUtc: '2026-03-13 22:22:00.000 UTC',
    eventType: 'DIRECT_MESSAGE_OUTBOUND',
    primaryParticipant: 'Examiner/Account Owner',
    secondaryParticipant: '12065550843@s.whatsapp.net',
    summary: 'Subject: "I extracted the CAD models and materials stress tables from the vault this afternoon."',
    associatedEvidenceId: '3EB0891C837EA01129DF',
    confidence: 'CONFIRMED',
    provenanceDetails: 'Source: msgstore.db (Row ID #190, Offset: 0x0002416C)',
    hasChronologyAnomaly: false
  },
  {
    eventId: 'TL-EVT-0004',
    timestampMs: 1773440640000,
    timestampUtc: '2026-03-13 22:24:00.000 UTC',
    eventType: 'DOCUMENT_TRANSMISSION',
    primaryParticipant: 'Examiner/Account Owner',
    secondaryParticipant: '12065550843@s.whatsapp.net',
    summary: 'Subject transmitted Apex_Falcon_Turbine_Schematic_v4.pdf (4.89 MB, SHA-256: a1b2c3d4...)',
    associatedEvidenceId: '3EB0901FA87BC42031EE',
    confidence: 'CONFIRMED',
    provenanceDetails: 'Source: msgstore.db + message_media table link',
    hasChronologyAnomaly: false
  },
  {
    eventId: 'TL-EVT-0005',
    timestampMs: 1773440800000,
    timestampUtc: '2026-03-13 22:26:40.000 UTC',
    eventType: 'DIRECT_MESSAGE_INBOUND',
    primaryParticipant: '12065550843@s.whatsapp.net',
    secondaryParticipant: 'Examiner/Account Owner',
    summary: 'Elena Rostova: "Blueprint received and checksum verified. Wire transfer confirmed."',
    associatedEvidenceId: '3EB0AA4182910FF49821',
    confidence: 'CONFIRMED',
    provenanceDetails: 'Source: msgstore.db (Row ID #192)',
    hasChronologyAnomaly: false
  },
  {
    eventId: 'TL-EVT-0006',
    timestampMs: 1773441000000,
    timestampUtc: '2026-03-13 22:30:00.000 UTC',
    eventType: 'DELETED_MESSAGE_CARVED',
    primaryParticipant: 'Examiner/Account Owner',
    secondaryParticipant: '12065550843@s.whatsapp.net',
    summary: '[RECOVERED FROM WAL] Subject: "PURGED BY USER: I am deleting our chat and wiping the SD cache now."',
    associatedEvidenceId: 'DEL-WAL-0048-REC01',
    confidence: 'CONFIRMED',
    provenanceDetails: 'Source: msgstore.db-wal (Frame #48, Offset: 0x00031400)',
    hasChronologyAnomaly: false
  },
  {
    eventId: 'TL-EVT-0007',
    timestampMs: 1773441120000,
    timestampUtc: '2026-03-13 22:32:00.000 UTC',
    eventType: 'DELETED_MESSAGE_CARVED',
    primaryParticipant: '12065550843@s.whatsapp.net',
    secondaryParticipant: 'Examiner/Account Owner',
    summary: '[RECOVERED FROM WAL] Elena Rostova: "Confirmation code for the vault deposit box is 9942-ALPHA-Z."',
    associatedEvidenceId: 'DEL-WAL-0049-REC02',
    confidence: 'CONFIRMED',
    provenanceDetails: 'Source: msgstore.db-wal (Frame #49, Offset: 0x00032400)',
    hasChronologyAnomaly: false
  },
  {
    eventId: 'TL-EVT-0008',
    timestampMs: 2060000000000,
    timestampUtc: '2035-04-12 11:33:20.000 UTC',
    eventType: 'CHRONOLOGY_ANOMALY',
    primaryParticipant: 'Examiner/Account Owner',
    secondaryParticipant: '14155550192@s.whatsapp.net',
    summary: 'Outbound message recorded with anomalous future epoch (Year 2035).',
    associatedEvidenceId: '3EB09999999999999999',
    confidence: 'CONFIRMED',
    provenanceDetails: 'Source: msgstore.db (Row ID #199)',
    hasChronologyAnomaly: true,
    anomalyExplanation: 'Timestamp occurs 9 years in the future relative to evidence seizure date (2026-03-14). Forensically indicative of manual device system clock manipulation or RTC oscillator failure.'
  }
];

export const SAMPLE_AUDIT_LOG: AuditLogEntry[] = [
  {
    entryId: 'AUD-00001',
    timestampUtc: '2026-03-14 09:20:15.000 UTC',
    actionType: 'CASE_INITIALIZATION',
    details: 'Initialized forensic workspace RB-2026-089 under Search Warrant #SW-2026-9041A. Examiner Marcus Vance authenticated.',
    examinerId: 'EX-9482',
    sha256VerificationStatus: 'VERIFIED_MATCH'
  },
  {
    entryId: 'AUD-00002',
    timestampUtc: '2026-03-14 09:32:10.120 UTC',
    actionType: 'EVIDENCE_INGESTION_LOCK',
    targetEvidenceId: 'EVID-001-MSGSTORE',
    details: 'Ingested msgstore.db (2.45 MB). Computed SHA-256: e3b0c44298fc1c14... Created write-blocked working replica.',
    examinerId: 'EX-9482',
    sha256VerificationStatus: 'VERIFIED_MATCH'
  },
  {
    entryId: 'AUD-00003',
    timestampUtc: '2026-03-14 09:32:11.450 UTC',
    actionType: 'EVIDENCE_INGESTION_LOCK',
    targetEvidenceId: 'EVID-002-WAL',
    details: 'Ingested companion msgstore.db-wal (512 KB). Computed SHA-256: 9f86d081884c7d65... Locked as read-only.',
    examinerId: 'EX-9482',
    sha256VerificationStatus: 'VERIFIED_MATCH'
  },
  {
    entryId: 'AUD-00004',
    timestampUtc: '2026-03-14 09:45:00.000 UTC',
    actionType: 'SQLITE_HEADER_VERIFICATION',
    targetEvidenceId: 'EVID-001-MSGSTORE',
    details: 'Parsed 100-byte SQLite header: Page Size = 4096, Write Version = 2 (WAL), Text Encoding = UTF-8, PRAGMA integrity_check = OK.',
    examinerId: 'EX-9482',
    sha256VerificationStatus: 'VERIFIED_MATCH'
  },
  {
    entryId: 'AUD-00005',
    timestampUtc: '2026-03-14 10:10:22.000 UTC',
    actionType: 'WAL_FRAME_CARVING_COMPLETED',
    targetEvidenceId: 'EVID-002-WAL',
    details: 'Completed forensic WAL frame scan across 128 frames. Identified 2 confirmed purged records (Frames #48 & #49). Classified under RogueByte Confidence Matrix.',
    examinerId: 'EX-9482',
    sha256VerificationStatus: 'VERIFIED_MATCH'
  },
  {
    entryId: 'AUD-00006',
    timestampUtc: '2026-03-14 11:05:40.000 UTC',
    actionType: 'CRYPTOGRAPHIC_REVERIFICATION',
    targetEvidenceId: 'ALL_EVIDENCE_FILES',
    details: 'Executed batch SHA-256 reverification across all 5 ingested evidence artifacts. Zero byte discrepancies detected (100% hash conformity).',
    examinerId: 'EX-9482',
    sha256VerificationStatus: 'VERIFIED_MATCH'
  }
];
