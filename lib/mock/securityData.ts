export interface SecurityFinding {
  id: string;
  ruleCode: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'COMPLIANT';
  title: string;
  description: string;
  remediation: string;
  engine: string;
  timestamp: string;
}

export interface MonitoredSession {
  id: string;
  initiator: string;
  responder: string;
  cipher: string;
  dhGroup: string;
  hash: string;
  pfs: 'YES' | 'NO' | 'WARN';
  trafficType: string;
  riskScore: number;
  status: 'ACTIVE' | 'SYNCHRONIZED' | 'CRIT' | 'DEGRADED';
  spiIn: string;
  spiOut: string;
  bytesTransferred: string;
  packets: number;
}

export interface PipelineStage {
  step: string;
  name: string;
  detail: string;
  meta: string;
  status: 'COMPLETED' | 'ACTIVE' | 'PENDING' | 'WARNING';
}

export const INITIAL_PIPELINE_STAGES: PipelineStage[] = [
  { step: '01', name: 'CAPTURE', detail: '65,421 pkts', meta: 'eth0 live feed', status: 'COMPLETED' },
  { step: '02', name: 'PARSE', detail: 'IKEv2 Grammars', meta: 'SA_INIT / AUTH', status: 'COMPLETED' },
  { step: '03', name: 'CORRELATE', detail: 'Child-SA Pairs', meta: 'SPI mapped', status: 'COMPLETED' },
  { step: '04', name: 'RFC AUDIT', detail: 'RFC 7296/4301', meta: '21 rules eval', status: 'COMPLETED' },
  { step: '05', name: 'CRYPTO', detail: 'Suite-B Profile', meta: 'Quantum Cleared', status: 'COMPLETED' },
  { step: '06', name: 'TRAFFIC ML', detail: 'Video Stream', meta: '91.4% confidence', status: 'COMPLETED' },
  { step: '07', name: 'RISK COMB', detail: 'Vector Synthesis', meta: 'Aggregating 3xS', status: 'ACTIVE' },
  { step: '08', name: 'RAG EXPLAIN', detail: 'Grounded Synth', meta: 'Awaiting pipeline', status: 'PENDING' },
];

export const MOCK_FINDINGS: SecurityFinding[] = [
  {
    id: 'F-01',
    ruleCode: 'RFC-C-027',
    severity: 'MEDIUM',
    title: 'PFS Disabled for Rekeyed Child SA (SPI: 0x9b4a2e1f)',
    description: 'Detected during CREATE_CHILD_SA rekeying negotiation. Exchange: No KEi/KEr key exchange payload was included, meaning the child SA derives keys directly from the original IKE SA key material without fresh DH computation.',
    remediation: 'set esp=aes256gcm16-modp2048! / pfs=yes',
    engine: 'RFC State Machine',
    timestamp: '04:18:21 UTC',
  },
  {
    id: 'F-02',
    ruleCode: 'SEC-D09',
    severity: 'HIGH',
    title: 'SA Lifetime Exceeds NTRO Hardening Baseline',
    description: 'Observed negotiated lifetime: 86,400s (24h). NTRO Hardening Direction 26160 mandates child SA rekey interval not exceed 7,200s (2h) or 10GB volume on perimeter IPsec gateways.',
    remediation: 'configure lifetime = 2h & margin-time = 10m',
    engine: 'Crypto Audit',
    timestamp: '04:18:20 UTC',
  },
  {
    id: 'F-03',
    ruleCode: 'META-D14',
    severity: 'LOW',
    title: 'Traffic Fingerprint: Video Streaming Frame Cadence',
    description: 'Inter-arrival time distribution and packet survey (1420-byte burst clusters at 33.3ms / 30Hz) allow an adversary observing outer ESP headers to fingerprint cleartext protocol as an RTP/H.264 video down-link.',
    remediation: 'enable traffic flow confidentiality (TFC) padding (RFC 4303 §2.7)',
    engine: 'ML Classifier',
    timestamp: '04:18:22 UTC',
  },
];

export const MOCK_SESSIONS: MonitoredSession[] = [
  {
    id: 'IPSEC-00421',
    initiator: '10.0.1.12:500',
    responder: '10.0.2.20:4500',
    cipher: 'AES-256-GCM',
    dhGroup: 'DH19',
    hash: 'SHA384',
    pfs: 'WARN',
    trafficType: 'H.264 RTP',
    riskScore: 82,
    status: 'ACTIVE',
    spiIn: '0x9b4a2e1f',
    spiOut: '0x3c8d197a',
    bytesTransferred: '482.4 MB',
    packets: 18419,
  },
  {
    id: 'IPSEC-00420',
    initiator: '10.0.1.14:500',
    responder: '10.0.2.20:4500',
    cipher: 'AES-128-CBC',
    dhGroup: 'DH14',
    hash: 'SHA256',
    pfs: 'YES',
    trafficType: 'HTTPS bulk',
    riskScore: 94,
    status: 'SYNCHRONIZED',
    spiIn: '0x4f12e801',
    spiOut: '0x7c9921b3',
    bytesTransferred: '1.2 GB',
    packets: 94201,
  },
  {
    id: 'IPSEC-00419',
    initiator: '192.168.4.11:500',
    responder: '10.0.2.20:4500',
    cipher: '3DES-CBC',
    dhGroup: 'DH2',
    hash: 'MD5',
    pfs: 'NO',
    trafficType: 'SNMP v2c',
    riskScore: 38,
    status: 'CRIT',
    spiIn: '0x12a9ef00',
    spiOut: '0x88f219da',
    bytesTransferred: '14.8 MB',
    packets: 4890,
  },
  {
    id: 'IPSEC-00418',
    initiator: '10.0.1.20:500',
    responder: '10.0.2.20:4500',
    cipher: 'ChaCha20-Poly1305',
    dhGroup: 'Curve25519',
    hash: 'SHA512',
    pfs: 'YES',
    trafficType: 'DNS Tunnel',
    riskScore: 76,
    status: 'SYNCHRONIZED',
    spiIn: '0x88c0349a',
    spiOut: '0x66df1287',
    bytesTransferred: '84.2 MB',
    packets: 23140,
  },
];
