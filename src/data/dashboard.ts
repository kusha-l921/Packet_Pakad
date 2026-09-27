import { SecurityScore } from '@/types';

export const mockSecurityScore: SecurityScore = {
  total: 82,
  max: 100,
  riskLevel: 'MEDIUM',
  compliancePercentage: 87,
  aiConfidence: 94.2,
  activeSessions: 24,
  assessedAt: '2 minutes ago',
  targetId: 'IPSEC-00421',
  breakdown: {
    cryptography: { current: 25, max: 30 },
    compliance: { current: 18, max: 20 },
    saSecurity: { current: 15, max: 20 },
    replayProtection: { current: 10, max: 10 },
    pfs: { current: 8, max: 10 },
    metadataExposure: { current: 6, max: 10 },
  },
  posture: {
    cryptoStrength: 'STRONG',
    configurationCompliance: 87,
    forwardSecrecy: true,
    replayProtection: true,
    metadataExposure: 'MEDIUM',
  },
};
