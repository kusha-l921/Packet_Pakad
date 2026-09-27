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
    cryptoStrength: 'WEAK' | 'ACCEPTABLE' | 'STRONG';
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
  source: string;
  destination: string;
  ikeVersion: IKEVersion;
  mode: IPsecMode;
  encryption: string;
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
  engineType: 'RULE ENGINE' | 'ML MODEL' | 'RAG ANALYSIS';
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
  encryption: 'AES-128' | 'AES-256' | 'AES-GCM' | 'AES-CBC-HMAC';
  authentication: 'PSK' | 'RSA-SIG' | 'ECDSA' | 'EAP-TLS';
  dhGroup: '14' | '19' | '20' | '21' | '31';
  pfs: boolean;
  ipVersion: 'IPv4' | 'IPv6';
  trafficType: 'Web' | 'VoIP' | 'Email' | 'Video' | 'ICMP';
  packetRate?: number;
  expectedSecurity?: 'WEAK' | 'ACCEPTABLE' | 'STRONG';
  profileCategory?: string;
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
