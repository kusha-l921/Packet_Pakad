export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ComplianceStatus = 'PASSED' | 'WARNING' | 'FAILED';
export type IKEVersion = 'IKEv1' | 'IKEv2';
export type IPsecMode = 'Tunnel' | 'Transport';
export type ProtocolType = 'ESP' | 'AH' | 'IKE';

export interface SecurityScoreBreakdown {
  cryptography: { current: number; max: number };
  compliance: { current: number; max: number };
  saSecurity: { current: number; max: number };
  replayProtection: { current: number; max: number };
  pfs: { current: number; max: number };
  metadataExposure: { current: number; max: number };
}

export interface SecurityScore {
  total: number;
  max: number;
  riskLevel: RiskLevel;
  compliancePercentage: number;
  aiConfidence: number;
  activeSessions: number;
  breakdown: SecurityScoreBreakdown;
  assessedAt: string;
  targetId: string;
  posture: {
    cryptoStrength: 'WEAK' | 'ACCEPTABLE' | 'STRONG' | 'BROKEN';
    configurationCompliance: number;
    forwardSecrecy: boolean;
    replayProtection: boolean;
    metadataExposure: 'LOW' | 'MEDIUM' | 'HIGH';
  };
}

export interface CryptoProfile {
  encryption: string;
  integrity: string;
  prf: string;
  dhGroup: string;
  pfsEnabled: boolean;
  esn: boolean;
  saLifetimeSec: number;
  keyExchangeType: string;
  similarity: {
    modernClassical: number; // e.g. 92%
    legacy: number;          // e.g. 21%
    pqcTransitional: number; // e.g. 48%
  };
  classificationCategory: 'MODERN CLASSICAL' | 'LEGACY DEPRECATED' | 'POST-QUANTUM HYBRID';
  complianceTags: string[];
}

export interface IKENegotiationStep {
  step: 'IKE_SA_INIT' | 'IKE_AUTH' | 'CREATE_CHILD_SA' | 'INFORMATIONAL';
  status: 'COMPLETED' | 'FAILED' | 'PENDING';
  timestamp: string;
  source: string;
  destination: string;
  exchangeId: number;
  messageId: number;
  payloads: string[];
  details: string;
  evidenceHex?: string;
}

export interface Session {
  id: string;
  rawId?: string;
  source: string;
  destination: string;
  ikeVersion: IKEVersion;
  mode: IPsecMode;
  encryption: string;
  cipher?: string;
  integrity?: string;
  dhGroup: string;
  pfs: boolean;
  trafficType: string;
  risk: RiskLevel;
  spiIn: string;
  spiOut: string;
  saLifetime: number;
  replayProtection: boolean;
  esnEnabled: boolean;
  packetsCount: number;
  bytesTransferred: number;
  status: 'ACTIVE' | 'TERMINATED' | 'REKEYING' | 'NEGOTIATING';
  establishedAt: string;
  ikeTimeline: IKENegotiationStep[];
  crypto: CryptoProfile;
  ragAnalysis?: {
    summary: string;
    groundedEvidence: string[];
    technicalRemediation: string;
    rfcCitations: string[];
  };
  trafficConfidence?: number;
  anomalyScore?: number;
  sideChannelRisk?: string;
}

export interface ComplianceFinding {
  id: string;
  ruleId: string; // e.g. RFC-C-014
  rfcRef: string; // e.g. RFC 7296 Section 2.5
  description: string;
  status: ComplianceStatus;
  engine: 'RULE ENGINE';
  evidence: string;
  recommendation: string;
  detectedInSession: string;
  impact: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface LiveWirePacket {
  id: number;
  seq: number;
  time: string;
  timeOffsetMs: number;
  size: number;
  rate: number;
  protocol: 'ESP' | 'TFC' | 'IKEv2';
  isPadding: boolean;
  isBurst: boolean;
  frameType: 'H.264 I-Frame' | 'Nominal P-Frame' | 'TFC Padding Frame' | 'DPD / Keepalive';
  entropy: number;
  direction: 'INGRESS' | 'EGRESS';
  spi: string;
  exposureRisk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'PROTECTED';
  details?: string;
}

export interface TrafficClassification {
  primaryClass: string; // e.g. VIDEO STREAMING
  confidence: number;   // e.g. 91.4%
  distribution: {
    label: string;
    percentage: number;
  }[];
  metrics: {
    packetRate: number;      // pkts/s
    averagePacketSize: number; // bytes
    burstActivity: 'LOW' | 'INTERMITTENT' | 'HIGH' | 'CONTINUOUS';
    directionality: string;  // e.g. 84% Ingress / 16% Egress
    flowDurationSec: number;
  };
  timelineData: {
    time: string;
    rate: number;
    size: number;
    isBurst: boolean;
  }[];
  packets?: LiveWirePacket[];
}

export interface AnomalyResult {
  score: number;       // e.g. 0.18
  threshold: number;   // 0.72
  status: 'NORMAL' | 'ANOMALOUS';
  models: {
    autoencoder: number;      // 0.16
    isolationForest: number;  // 0.20
  };
  explanation: string;
}

export interface MetadataExposure {
  risk: RiskLevel;
  fingerprintingDetected: boolean;
  timingPatterns: boolean;
  burstPatterns: boolean;
  directionalityFingerprint: boolean;
  exposureScore: number; // 0-100
  notes: string;
  timelineObservations: {
    time: string;
    event: string;
    leakageType: string;
  }[];
}

export interface ThreatFinding {
  id: string;
  title: string;
  severity: RiskLevel;
  session: string;
  likelihood: number; // 1 to 5
  impact: number;     // 1 to 5
  category: 'CRYPTOGRAPHY' | 'COMPLIANCE' | 'METADATA' | 'ANOMALY' | 'SA_LIFETIME';
  detectedStage: string;
  evidence: string;
  recommendation: string;
  engineType: 'RULE ENGINE' | 'ML MODEL' | 'DEEP AUDIT';
  timestamp: string;
}

export interface Packet {
  id: number;
  timestamp: string;
  source: string;
  destination: string;
  protocol: ProtocolType;
  info: string;
  length: number;
  spi?: string;
  seq?: number;
  flags?: string;
  rawHexPreview?: string;
}

export interface AnalysisPipelineStage {
  id: string;
  name: string;
  engine: 'RULE' | 'ML' | 'RAG';
  status: 'PENDING' | 'ACTIVE' | 'COMPLETED' | 'FAILED';
  description: string;
}

export interface TestbedConfiguration {
  id?: string;
  ikeVersion: IKEVersion;
  mode: IPsecMode;
  encryption: 'AES-128' | 'AES-256' | 'AES-GCM' | 'AES-CBC-HMAC' | string;
  authentication?: 'PSK' | 'RSA-SIG' | 'ECDSA' | 'EAP-TLS' | string;
  dhGroup: '14' | '19' | '20' | '21' | '31' | string;
  pfs: boolean;
  ipVersion: 'IPv4' | 'IPv6';
  trafficType: 'Web' | 'VoIP' | 'Email' | 'Video' | 'ICMP';
  packetRate?: number;
  expectedSecurity?: 'WEAK' | 'ACCEPTABLE' | 'STRONG';
  profileCategory?: string;
  ikeProposalSuite?: number;
  espProposalSuite?: number;
  keyExchangeRounds?: number;
  primaryKeyExchange?: string;
  additionalKeyExchange1?: string;
  additionalKeyExchange2?: string;
  childSaCount?: number;
  saInitTransforms?: {
    encr?: string;
    prf?: string;
    integ?: string;
    ke?: string;
  };
  childSaTransforms?: {
    encr?: string;
    integ?: string;
    dh?: string;
    esn?: string;
  };
}

export interface Report {
  id: string;
  title: string;
  type: 'EXECUTIVE' | 'TECHNICAL';
  generatedAt: string;
  targetSessionId: string;
  author: string;
  executiveSummary?: {
    securityScore: number;
    risk: RiskLevel;
    complianceScore: number;
    topFindings: string[];
    businessImpact: string;
    highLevelRecommendations: string[];
  };
  technicalSummary?: {
    sessionOverview: Session;
    cryptoAudit: CryptoProfile;
    rfcComplianceStats: {
      total: number;
      passed: number;
      warnings: number;
      failed: number;
    };
    mlInference: TrafficClassification;
    anomalyDetails: AnomalyResult;
    metadataRisk: MetadataExposure;
    groundedEvidencePoints: string[];
  };
}

export interface DatasetMetrics {
  totalSamples: number;
  trainSplit: number;
  valSplit: number;
  testSplit: number;
  classes: {
    className: string;
    count: number;
    pct: number;
  }[];
  configs: {
    label: string;
    count: number;
  }[];
  groundTruthAccuracy: {
    class: string;
    precision: number;
    recall: number;
    f1: number;
  }[];
}

export interface CertFinding {
  rule_id: string;
  status: 'PASS' | 'WARNING' | 'FAIL' | 'INFORMATIONAL';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  target: string;
  condition: string;
  observed: string;
  expected: string;
  reason: string;
  remediation: string;
}

export interface CertRating {
  tier: string;
  score: number;
  security_bits: number;
  cnsa_2_0_compliant: boolean;
  nist_modern_compliant: boolean;
  rfc8247_compliant: boolean;
  reason: string;
  recommendation: string;
}

export interface LeafCertificate {
  index: number;
  cert_type: string;
  subject: string;
  issuer: string;
  serial_number: string;
  is_ca: boolean;
  key_type_oid: string;
  key_type_name: string;
  key_bits: number;
  sig_algo_oid: string;
  sig_algo_name: string;
  not_before: number;
  not_after: number;
  days_until_expiration: number;
  health_status: 'HEALTHY' | 'EXPIRING_SOON' | 'EXPIRED' | 'NOT_YET_VALID' | 'CRITICAL_DEFECT';
  rating: CertRating;
  findings: CertFinding[];
}

export interface CertPeerAudit {
  peer: 'initiator' | 'responder' | string;
  identity: {
    type: number | string;
    value: string;
  };
  auth_method: number | string;
  peer_status: string;
  chain_length: number;
  leaf_certificate: LeafCertificate;
  chain_certificates: LeafCertificate[];
  findings: CertFinding[];
}

export interface CertificateHealthReport {
  overall_health_status: 'HEALTHY' | 'EXPIRING_SOON' | 'EXPIRED' | 'DEGRADED' | 'CRITICAL';
  is_compliant: boolean;
  reference_time: number;
  summary: {
    total_certificates_audited: number;
    critical_failures_count: number;
    warnings_count: number;
    passed_count: number;
  };
  peers: {
    initiator?: CertPeerAudit;
    responder?: CertPeerAudit;
    [key: string]: CertPeerAudit | undefined;
  };
  findings: CertFinding[];
}
