/**
 * RogueByte WhatsApp Forensics Ultimate v2.0 - Sample Network Forensic Dataset
 * Matter: Case RB-2026-089 (Apex Propulsion IP Exfiltration)
 * Correlated Lawful Network Packet Capture: capture_cellular_s23.pcap
 */

import {
  IPRecord,
  NetworkFlow,
  DNSRecord,
  CallNetworkCorrelation,
  MessageNetworkCorrelation
} from '../types/forensics';

export const SAMPLE_IP_RECORDS: IPRecord[] = [
  {
    ipAddress: '157.240.22.35',
    addressFamily: 'IPv4',
    classification: 'PUBLIC',
    sourceFile: 'capture_cellular_s23.pcap',
    firstSeenUtc: '2026-03-13 22:19:58.120 UTC',
    lastSeenUtc: '2026-03-13 22:31:02.440 UTC',
    protocols: ['TCP', 'TLS'],
    ports: [443],
    packetReferences: [14, 15, 42, 88],
    asnInfo: {
      asn: 32934,
      asName: 'FACEBOOK',
      organization: 'Meta Platforms, Inc. (WhatsApp Infrastructure)',
      countryCode: 'US',
      cidrPrefix: '157.240.0.0/16',
      isMetaInfrastructure: true
    },
    geolocation: {
      country: 'United States',
      region: 'California',
      city: 'Menlo Park',
      latitude: 37.4530,
      longitude: -122.1817,
      disclaimer: 'IP geolocation is an estimate of network location. It does not establish a person\'s exact physical location.'
    },
    reputation: {
      threatScore: 0,
      categories: ['Verified Meta/WhatsApp Edge Infrastructure'],
      isFlaggedProxy: false,
      isFlaggedVpn: false
    },
    attributionLimitations: 'Server endpoint owned by Meta Platforms. Does not identify individual WhatsApp users.'
  },
  {
    ipAddress: '31.13.86.36',
    addressFamily: 'IPv4',
    classification: 'PUBLIC',
    sourceFile: 'capture_cellular_s23.pcap',
    firstSeenUtc: '2026-03-13 22:21:40.000 UTC',
    lastSeenUtc: '2026-03-13 22:23:10.500 UTC',
    protocols: ['UDP', 'STUN/TURN'],
    ports: [3478, 45210],
    packetReferences: [102, 103, 104, 105, 120],
    asnInfo: {
      asn: 32934,
      asName: 'FACEBOOK',
      organization: 'Meta Platforms, Inc. (WhatsApp Call Relays)',
      countryCode: 'IE',
      cidrPrefix: '31.13.64.0/18',
      isMetaInfrastructure: true
    },
    geolocation: {
      country: 'Ireland',
      region: 'Leinster',
      city: 'Dublin',
      latitude: 53.3498,
      longitude: -6.2603,
      disclaimer: 'IP geolocation is an estimate of network location. It does not establish a person\'s exact physical location.'
    },
    reputation: {
      threatScore: 0,
      categories: ['WhatsApp STUN/TURN Voice Relay'],
      isFlaggedProxy: false,
      isFlaggedVpn: false
    },
    attributionLimitations: 'Intermediary media relay. Traffic routing through this IP does not expose the remote peer IP.'
  },
  {
    ipAddress: '195.186.210.88',
    addressFamily: 'IPv4',
    classification: 'PUBLIC',
    sourceFile: 'capture_cellular_s23.pcap',
    firstSeenUtc: '2026-03-13 22:28:15.000 UTC',
    lastSeenUtc: '2026-03-13 22:29:40.200 UTC',
    protocols: ['TCP', 'TLS'],
    ports: [443],
    packetReferences: [210, 211, 215],
    asnInfo: {
      asn: 3303,
      asName: 'SWISSCOM',
      organization: 'Swisscom Enterprise Services (Zurich Data Center)',
      countryCode: 'CH',
      cidrPrefix: '195.186.0.0/16',
      isMetaInfrastructure: false
    },
    geolocation: {
      country: 'Switzerland',
      region: 'Zurich',
      city: 'Zurich',
      latitude: 47.3769,
      longitude: 8.5417,
      disclaimer: 'IP geolocation is an estimate of network location. It does not establish a person\'s exact physical location.'
    },
    reputation: {
      threatScore: 5,
      categories: ['Swiss Financial Network / Banking Gateway'],
      isFlaggedProxy: false,
      isFlaggedVpn: false
    },
    attributionLimitations: 'Financial enterprise endpoint in Zurich matching transfer confirmation discussed in Elena Rostova chat.'
  },
  {
    ipAddress: '192.168.1.50',
    addressFamily: 'IPv4',
    classification: 'PRIVATE',
    sourceFile: 'capture_cellular_s23.pcap',
    firstSeenUtc: '2026-03-13 22:19:50.000 UTC',
    lastSeenUtc: '2026-03-13 22:35:00.000 UTC',
    protocols: ['TCP', 'UDP', 'DNS'],
    ports: [52114, 48102, 34780],
    packetReferences: [1, 2, 3, 14, 102],
    attributionLimitations: 'Internal Wi-Fi / LAN IP assigned by DHCP router to the subject device (Samsung Galaxy S23).'
  },
  {
    ipAddress: '8.8.8.8',
    addressFamily: 'IPv4',
    classification: 'PUBLIC',
    sourceFile: 'capture_cellular_s23.pcap',
    firstSeenUtc: '2026-03-13 22:19:52.000 UTC',
    lastSeenUtc: '2026-03-13 22:19:53.000 UTC',
    protocols: ['UDP', 'DNS'],
    ports: [53],
    packetReferences: [1, 2],
    asnInfo: {
      asn: 15169,
      asName: 'GOOGLE',
      organization: 'Google LLC Public Resolver',
      countryCode: 'US',
      cidrPrefix: '8.8.8.8/32',
      isMetaInfrastructure: false
    },
    attributionLimitations: 'Public recursive DNS resolver.'
  }
];

export const SAMPLE_NETWORK_FLOWS: NetworkFlow[] = [
  {
    flowId: 'FLOW-00001',
    srcIp: '192.168.1.50',
    dstIp: '8.8.8.8',
    srcPort: 52114,
    dstPort: 53,
    protocol: 'DNS',
    packetCount: 2,
    byteCount: 168,
    startTimeUtc: '2026-03-13 22:19:52.100 UTC',
    endTimeUtc: '2026-03-13 22:19:52.150 UTC',
    durationSeconds: 0.05,
    serviceHint: 'DNS Resolution for e1.whatsapp.net',
    tcpFlagsObserved: []
  },
  {
    flowId: 'FLOW-00002',
    srcIp: '192.168.1.50',
    dstIp: '157.240.22.35',
    srcPort: 48102,
    dstPort: 443,
    protocol: 'TCP',
    packetCount: 142,
    byteCount: 4982100,
    startTimeUtc: '2026-03-13 22:20:00.000 UTC',
    endTimeUtc: '2026-03-13 22:26:50.000 UTC',
    durationSeconds: 410.0,
    serviceHint: 'WhatsApp Messaging & Schematic Document Transfer (Port 443 TLS)',
    tcpFlagsObserved: ['SYN', 'ACK', 'PSH']
  },
  {
    flowId: 'FLOW-00003',
    srcIp: '192.168.1.50',
    dstIp: '31.13.86.36',
    srcPort: 34780,
    dstPort: 3478,
    protocol: 'STUN/TURN',
    packetCount: 840,
    byteCount: 142800,
    startTimeUtc: '2026-03-13 22:21:40.000 UTC',
    endTimeUtc: '2026-03-13 22:22:28.000 UTC',
    durationSeconds: 48.0,
    serviceHint: 'WhatsApp Encrypted Voice Call Session (STUN Binding & SRTP Relay)',
    tcpFlagsObserved: []
  },
  {
    flowId: 'FLOW-00004',
    srcIp: '192.168.1.50',
    dstIp: '195.186.210.88',
    srcPort: 51234,
    dstPort: 443,
    protocol: 'TCP',
    packetCount: 38,
    byteCount: 24900,
    startTimeUtc: '2026-03-13 22:28:15.000 UTC',
    endTimeUtc: '2026-03-13 22:29:40.200 UTC',
    durationSeconds: 85.2,
    serviceHint: 'Swiss Cantonal Wire Transfer Confirmation (Zurich Gateway)',
    tcpFlagsObserved: ['SYN', 'ACK', 'PSH', 'FIN']
  }
];

export const SAMPLE_DNS_RECORDS: DNSRecord[] = [
  {
    queryId: 4660,
    timestampUtc: '2026-03-13 22:19:52.100 UTC',
    queryName: 'e1.whatsapp.net',
    queryType: 'A',
    responseIps: ['157.240.22.35'],
    responseCode: 'NOERROR',
    packetNumber: 1,
    sourceIp: '192.168.1.50',
    destinationIp: '8.8.8.8'
  },
  {
    queryId: 4661,
    timestampUtc: '2026-03-13 22:21:38.200 UTC',
    queryName: 'turn.whatsapp.net',
    queryType: 'A',
    responseIps: ['31.13.86.36'],
    responseCode: 'NOERROR',
    packetNumber: 99,
    sourceIp: '192.168.1.50',
    destinationIp: '8.8.8.8'
  },
  {
    queryId: 4662,
    timestampUtc: '2026-03-13 22:28:10.000 UTC',
    queryName: 'secure.swiss-vault-transfer.ch',
    queryType: 'A',
    responseIps: ['195.186.210.88'],
    responseCode: 'NOERROR',
    packetNumber: 205,
    sourceIp: '192.168.1.50',
    destinationIp: '8.8.8.8'
  }
];

export const SAMPLE_CALL_CORRELATIONS: CallNetworkCorrelation[] = [
  {
    callId: 'CALL-2026-03-13-WA01',
    callType: 'voice',
    callStartUtc: '2026-03-13 22:21:40.000 UTC',
    callEndUtc: '2026-03-13 22:22:28.000 UTC',
    callDurationSeconds: 48,
    participantJid: '12065550843@s.whatsapp.net',
    candidateFlows: [SAMPLE_NETWORK_FLOWS[2]],
    observedEndpoints: [SAMPLE_IP_RECORDS[1]],
    classification: 'IDENTIFIED_SERVICE_INFRASTRUCTURE',
    attributionDisclaimer:
      'FORENSIC EVIDENTIARY LIMITATION: WhatsApp voice and video calls utilize intermediary infrastructure, STUN/TURN relays, carrier-grade NAT, and VPNs. Encrypted RTP/SRTP traffic observed during a call window does NOT establish that an observed IP address belongs directly to the remote participant without carrier subscriber logs and lawful intercept verification.',
    examinerRationale:
      'Observed 840 UDP packets on port 3478 to Meta Infrastructure (AS32934 in Dublin) conforming precisely to call start/end epoch. Classified as Meta relay server, NOT the direct physical IP address of Elena Rostova.'
  }
];

export const SAMPLE_MESSAGE_CORRELATIONS: MessageNetworkCorrelation[] = [
  {
    messageId: '3EB0901FA87BC42031EE',
    messageTimestampUtc: '2026-03-13 22:24:00.000 UTC',
    senderJid: 'Examiner/Account Owner',
    remoteJid: '12065550843@s.whatsapp.net',
    candidateFlows: [SAMPLE_NETWORK_FLOWS[1]],
    timeDeltaSeconds: 0.42,
    confidenceLevel: 'HIGH_TEMPORAL_ALIGNMENT',
    attributionDisclaimer:
      'Observed TCP flow to Meta Platforms IP 157.240.22.35 on port 443 corresponds temporally to document transmission timestamp. Server IP identifies Meta edge proxy, not the destination subscriber device.',
    examinerRationale:
      'High traffic burst (4.98 MB) over TLS coincides with transmission of Apex_Falcon_Turbine_Schematic_v4.pdf.'
  }
];
