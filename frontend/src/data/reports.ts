import { Report } from '@/types';
import { mockSessions } from './sessions';
import { mockTrafficClassification, mockAnomalyResult, mockMetadataExposure } from './traffic';

export const mockExecutiveReport: Report = {
  id: 'REP-EXEC-2026-0042',
  title: 'Executive Security Posture Assessment: Border IPsec Tunnel Infrastructure',
  type: 'EXECUTIVE',
  generatedAt: '2026-09-27 15:30 UTC',
  targetSessionId: 'IPSEC-00421',
  author: 'Packet Pakad Autonomous Evaluator',
  executiveSummary: {
    securityScore: 82,
    risk: 'MEDIUM',
    complianceScore: 87,
    topFindings: [
      'Child-SA Rekeying lacks Perfect Forward Secrecy (PFS), retaining legacy parent session master key exposure.',
      'Cryptographic suite utilizes modern classical AES-256-GCM and DH Group 19, meeting contemporary sovereign standards.',
      'Unpadded video streaming telepresence traffic exhibits distinct 33.3ms packet burst cadence, enabling traffic-fingerprinting side-channel leaks.',
    ],
    businessImpact: 'While active session payload encryption resists direct brute-force cryptanalysis, side-channel metadata analysis allows foreign signal interception posts to infer operational command tempos, videoconference schedules, and peer endpoints. Rekeying without PFS leaves retrospective recorded traffic vulnerable if gateway state is ever compromised.',
    highLevelRecommendations: [
      'Mandate strict PFS across all gateway configurations via swanctl/strongSwan rekeying policies.',
      'Enable ESP Traffic Flow Confidentiality (TFC) padding to equalize packet size distributions and thwart traffic classification.',
      'Decommission legacy tunnels (IPSEC-00419 running 3DES/MD5) within 48 hours to eliminate Sweet32 collision exposure.',
      'Initiate pilot testing of Post-Quantum Cryptography (PQC) hybrid key exchange (RFC 9370) for next-generation sovereign communication lines.',
    ],
  },
};

export const mockTechnicalReport: Report = {
  id: 'REP-TECH-2026-0098',
  title: 'In-Depth Technical Cryptographic and Protocol Dissection: Session IPSEC-00421',
  type: 'TECHNICAL',
  generatedAt: '2026-09-27 15:30 UTC',
  targetSessionId: 'IPSEC-00421',
  author: 'Security Operations & Protocol Analysis Unit',
  technicalSummary: {
    sessionOverview: mockSessions[0],
    cryptoAudit: mockSessions[0].crypto,
    rfcComplianceStats: {
      total: 24,
      passed: 18,
      warnings: 4,
      failed: 2,
    },
    mlInference: mockTrafficClassification,
    anomalyDetails: mockAnomalyResult,
    metadataRisk: mockMetadataExposure,
    groundedEvidencePoints: [
      'Deterministic RFC Engine: Evaluated against RFC 7296 (IKEv2), RFC 4303 (ESP), RFC 8221 (Cipher Suite Requirements).',
      'IKE Exchange Trace: Initiator SPI 0x3c8d197a, Responder SPI 0x9b4a2e1f. Exchange #0 succeeded with proposal #1.',
      'Rekey Dissection: Message #2 (CREATE_CHILD_SA) contains N(REKEY_SA) without KEi payload. Result: PFS violation.',
      'Anti-Replay Window: 64-packet bitmap verified with 64-bit Extended Sequence Numbers (ESN). Zero out-of-order drop events.',
      'Traffic Classifier: Random forest & 1D-CNN temporal model classified stream as H.264 Video Streaming with 91.4% confidence.',
    ],
  },
};
