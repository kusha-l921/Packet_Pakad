import { TrafficClassification, AnomalyResult, MetadataExposure } from '@/types';

export const mockTrafficTimeline = [
  { time: '14:32:00', rate: 120, size: 420, isBurst: false },
  { time: '14:32:05', rate: 145, size: 510, isBurst: false },
  { time: '14:32:10', rate: 310, size: 980, isBurst: true },
  { time: '14:32:15', rate: 580, size: 1380, isBurst: true },
  { time: '14:32:20', rate: 610, size: 1420, isBurst: true },
  { time: '14:32:25', rate: 290, size: 850, isBurst: false },
  { time: '14:32:30', rate: 180, size: 460, isBurst: false },
  { time: '14:32:35', rate: 640, size: 1440, isBurst: true },
  { time: '14:32:40', rate: 590, size: 1390, isBurst: true },
  { time: '14:32:45', rate: 210, size: 520, isBurst: false },
  { time: '14:32:50', rate: 160, size: 440, isBurst: false },
  { time: '14:32:55', rate: 670, size: 1460, isBurst: true },
];

export const mockTrafficClassification: TrafficClassification = {
  primaryClass: 'VIDEO STREAMING (H.264 / RTP)',
  confidence: 91.4,
  distribution: [
    { label: 'Video Streaming', percentage: 91.4 },
    { label: 'Web (HTTPS)', percentage: 5.2 },
    { label: 'Other Encrypted', percentage: 3.4 },
  ],
  metrics: {
    packetRate: 482,
    averagePacketSize: 1120,
    burstActivity: 'INTERMITTENT',
    directionality: '84% Ingress / 16% Egress',
    flowDurationSec: 3600,
  },
  timelineData: mockTrafficTimeline,
};

export const mockAnomalyResult: AnomalyResult = {
  score: 0.18,
  threshold: 0.72,
  status: 'NORMAL',
  models: {
    autoencoder: 0.16,
    isolationForest: 0.20,
  },
  explanation: 'Current flow behavioral features (packet timing dispersion, inter-arrival entropy, and packet size distribution) fall safely within nominal bounds for standard telepresence streams.',
};

export const mockAnomalousResult: AnomalyResult = {
  score: 0.91,
  threshold: 0.72,
  status: 'ANOMALOUS',
  models: {
    autoencoder: 0.89,
    isolationForest: 0.93,
  },
  explanation: 'Anomalous exfiltration signature detected. Sustained maximum transmission unit (MTU 1500) bursts with near-zero inter-arrival jitter inconsistent with negotiated profile.',
};

export const mockMetadataExposure: MetadataExposure = {
  risk: 'MEDIUM',
  fingerprintingDetected: true,
  timingPatterns: true,
  burstPatterns: true,
  directionalityFingerprint: true,
  exposureScore: 58,
  notes: 'Encrypted ESP payloads hide plaintext content, but lack of Traffic Flow Confidentiality (TFC) padding allows an adversary monitoring the wire to infer application behavior, frame rate (30fps), and speech activity patterns.',
  timelineObservations: [
    {
      time: '14:32:19',
      event: 'Fixed Frame Duration Spike (33.3ms)',
      leakageType: 'Video Frame Cadence',
    },
    {
      time: '14:32:22',
      event: 'Asymmetric 84:16 Downstream Ratio',
      leakageType: 'Client-Server Role Inference',
    },
    {
      time: '14:32:26',
      event: '1420-Byte Packet Clumping',
      leakageType: 'H.264 I-Frame Size Fingerprint',
    },
    {
      time: '14:32:38',
      event: 'Voice Activity Detection (VAD) Pause',
      leakageType: 'Conversational Silence Correlation',
    },
  ],
};
