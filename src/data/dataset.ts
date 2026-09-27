import { DatasetMetrics } from '@/types';

export const mockDatasetMetrics: DatasetMetrics = {
  totalSamples: 250000,
  trainSplit: 175000,
  valSplit: 37500,
  testSplit: 37500,
  classes: [
    { className: 'Video Teleconference (H.264/RTP)', count: 92400, pct: 37.0 },
    { className: 'Web Encrypted (HTTPS/TLS 1.3)', count: 68500, pct: 27.4 },
    { className: 'VoIP Audio Streams (Opus/G.711)', count: 44200, pct: 17.7 },
    { className: 'Email / Messaging (IMAP/SMTP/TLS)', count: 28900, pct: 11.6 },
    { className: 'ICMP / Network Keepalives', count: 16000, pct: 6.4 },
  ],
  configs: [
    { label: 'IKEv2 / Tunnel / AES-256-GCM / DH19 / PFS ON / IPv4', count: 68000 },
    { label: 'IKEv2 / Tunnel / AES-128-CBC / DH14 / PFS OFF / IPv4', count: 52000 },
    { label: 'IKEv2 / Tunnel / ChaCha20-Poly1305 / DH31 / PFS ON / IPv6', count: 48000 },
    { label: 'IKEv1 / Tunnel / 3DES-CBC / DH2 / PFS OFF / IPv4 (Legacy)', count: 32000 },
    { label: 'IKEv2 / Transport / AES-256-GCM / DH19 / PFS ON / IPv6', count: 28000 },
    { label: 'IKEv2 / Hybrid-PQC / Kyber768+DH19 / PFS ON / IPv6', count: 22000 },
  ],
  groundTruthAccuracy: [
    { class: 'Video Teleconference', precision: 0.942, recall: 0.928, f1: 0.935 },
    { class: 'Web Encrypted', precision: 0.891, recall: 0.914, f1: 0.902 },
    { class: 'VoIP Audio', precision: 0.965, recall: 0.951, f1: 0.958 },
    { class: 'Email / Messaging', precision: 0.884, recall: 0.872, f1: 0.878 },
    { class: 'ICMP / Keepalive', precision: 0.998, recall: 0.995, f1: 0.996 },
  ],
};
