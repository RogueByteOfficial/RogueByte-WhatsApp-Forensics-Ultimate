/**
 * RogueByte WhatsApp Forensics Ultimate - Type Definitions
 * Brand: RogueByteOfficial
 */

export type ConfidenceCategory = 
  | 'CONFIRMED'      // Structurally validated record with intact fields & primary keys
  | 'PARTIAL'        // Fragmentary record with readable text but missing relational IDs
  | 'INFERRED'       // Analytical deduction based on surrounding references/metadata
  | 'UNVERIFIED'     // Raw unallocated carver hit lacking relational validation
  | 'UNRECOVERABLE'; // Overwritten or corrupted beyond reliable forensic recovery

export type EvidenceSourceType =
  | 'SQLITE_ACTIVE'
  | 'SQLITE_WAL'
  | 'SQLITE_JOURNAL'
  | 'UNALLOCATED_PAGE'
  | 'FREELIST_BLOCK'
  | 'BACKUP_CRYPT'
  | 'CHAT_EXPORT'
  | 'MEDIA_FILE'
  | 'NETWORK_PCAP';

export type IPClassification =
  | 'PUBLIC'
  | 'PRIVATE'
  | 'LOOPBACK'
  | 'LINK_LOCAL'
  | 'MULTICAST'
  | 'RESERVED'
  | 'SPECIAL_PURPOSE';

export type CallCorrelationClass =
  | 'OBSERVED_ENDPOINT'
  | 'POSSIBLE_CALL_ASSOCIATION'
  | 'IDENTIFIED_SERVICE_INFRASTRUCTURE'
  | 'REMOTE_PARTICIPANT_IP_UNCONFIRMED'
  | 'INSUFFICIENT_EVIDENCE';

export interface ASNInfo {
  asn: number;
  asName: string;
  organization: string;
  countryCode: string;
  cidrPrefix: string;
  isMetaInfrastructure: boolean;
}

export interface GeolocationEstimate {
  country: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  disclaimer: string;
}

export interface IPReputationInfo {
  threatScore: number;
  categories: string[];
  isFlaggedProxy: boolean;
  isFlaggedVpn: boolean;
}

export interface IPRecord {
  ipAddress: string;
  addressFamily: 'IPv4' | 'IPv6';
  classification: IPClassification;
  sourceFile: string;
  firstSeenUtc?: string;
  lastSeenUtc?: string;
  protocols: string[];
  ports: number[];
  packetReferences: number[];
  asnInfo?: ASNInfo;
  geolocation?: GeolocationEstimate;
  reputation?: IPReputationInfo;
  attributionLimitations: string;
}

export interface NetworkFlow {
  flowId: string;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'DNS' | 'STUN/TURN' | 'OTHER';
  packetCount: number;
  byteCount: number;
  startTimeUtc: string;
  endTimeUtc: string;
  durationSeconds: number;
  serviceHint?: string;
  tcpFlagsObserved: string[];
}

export interface DNSRecord {
  queryId: number;
  timestampUtc: string;
  queryName: string;
  queryType: string;
  responseIps: string[];
  responseCode: string;
  packetNumber: number;
  sourceIp: string;
  destinationIp: string;
}

export interface CallNetworkCorrelation {
  callId: string;
  callType: 'voice' | 'video';
  callStartUtc: string;
  callEndUtc: string;
  callDurationSeconds: number;
  participantJid: string;
  candidateFlows: NetworkFlow[];
  observedEndpoints: IPRecord[];
  classification: CallCorrelationClass;
  attributionDisclaimer: string;
  examinerRationale: string;
}

export interface MessageNetworkCorrelation {
  messageId: string;
  messageTimestampUtc: string;
  senderJid: string;
  remoteJid: string;
  candidateFlows: NetworkFlow[];
  timeDeltaSeconds: number;
  confidenceLevel: 'HIGH_TEMPORAL_ALIGNMENT' | 'MODERATE' | 'LOW';
  attributionDisclaimer: string;
  examinerRationale: string;
}

export type MessageType =
  | 'text'
  | 'image'
  | 'audio'
  | 'video'
  | 'document'
  | 'sticker'
  | 'location'
  | 'contact'
  | 'call'
  | 'revoked'
  | 'system';

export interface EvidenceArtifact {
  evidenceId: string;
  filename: string;
  fileSizeBytes: number;
  sha256Hash: string;
  importTimestampUtc: string;
  sourceType: EvidenceSourceType;
  magicBytes: string;
  isReadOnly: boolean;
  notes?: string;
  devicePlatform?: 'Android' | 'iOS' | 'Desktop' | 'Unknown';
  schemaVersion?: string;
}

export interface MessageRecord {
  messageId: string;
  remoteJid: string;
  senderJid: string;
  senderName?: string;
  isFromMe: boolean;
  timestampMs: number;
  timestampUtc: string;
  textContent: string | null;
  messageType: MessageType;
  status: 'received' | 'sent' | 'delivered' | 'read' | 'played';
  mediaUrl?: string;
  mediaPath?: string;
  mediaSha256?: string;
  mediaSizeBytes?: number;
  mediaDurationSeconds?: number;
  quotedMessageId?: string;
  confidence: ConfidenceCategory;
  sourceType: EvidenceSourceType;
  sourceOffset?: number;
  sourceFile: string;
  isDeleted: boolean;
  recoveryMethod?: string;
  notes?: string;
}

export interface ConversationRecord {
  jid: string;
  displayName: string;
  isGroup: boolean;
  totalMessages: number;
  activeMessages: number;
  deletedRecoveredMessages: number;
  lastActivityUtc: string;
  participants: string[];
}

export interface ContactRecord {
  jid: string;
  displayName: string;
  phoneNumber?: string;
  status?: string;
  isGroup: boolean;
  messageCount: number;
  avatarUrl?: string;
}

export interface DeletedCandidate {
  candidateId: string;
  sourceFile: string;
  byteOffset: number;
  rawPayloadHex: string;
  decodedText: string | null;
  confidence: ConfidenceCategory;
  recoveryMechanism: string;
  structuralValidationPass: boolean;
  fieldIntegrity: {
    jidIntact: boolean;
    payloadIntact: boolean;
    keyIdIntact: boolean;
  };
  examinerRationale: string;
}

export interface TimelineEvent {
  eventId: string;
  timestampMs: number;
  timestampUtc: string;
  eventType: string;
  primaryParticipant: string;
  secondaryParticipant: string;
  summary: string;
  associatedEvidenceId: string;
  confidence: ConfidenceCategory;
  provenanceDetails: string;
  hasChronologyAnomaly: boolean;
  anomalyExplanation?: string;
}

export interface AuditLogEntry {
  entryId: string;
  timestampUtc: string;
  actionType: string;
  targetEvidenceId?: string;
  details: string;
  examinerId: string;
  sha256VerificationStatus: 'VERIFIED_MATCH' | 'HASH_MISMATCH' | 'PENDING';
}

export interface CaseMetadata {
  caseId: string;
  caseTitle: string;
  examinerName: string;
  examinerId: string;
  agencyName: string;
  authorizationReference: string;
  creationTimestampUtc: string;
  lastModifiedUtc: string;
  notes: string;
}

export interface BenchmarkMetrics {
  benchmarkName: string;
  executionDurationMs: number;
  activeMessagePrecision: number;
  activeMessageRecall: number;
  falsePositiveRate: number;
  databaseIntegrityPassed: boolean;
  sqlitePageSizeMatched: boolean;
  chronologyAnomalyDetectionRate: number;
  cryptographicIntegrityVerification: string;
  carvedSlackCandidatesFound: number;
  status: 'PASS' | 'FAIL';
  groundTruth: {
    expectedActive: number;
    recoveredActive: number;
    expectedAnomalies: number;
    detectedAnomalies: number;
    expectedChats: number;
    discoveredChats: number;
  };
}
