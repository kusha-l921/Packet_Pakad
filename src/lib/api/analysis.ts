import {
  SecurityScore,
  ComplianceFinding,
  ThreatFinding,
  TrafficClassification,
  AnomalyResult,
  MetadataExposure,
} from '@/types';
import { mockSecurityScore } from '@/data/dashboard';
import { mockComplianceFindings, mockThreatFindings } from '@/data/findings';
import {
  mockTrafficClassification,
  mockAnomalyResult,
  mockMetadataExposure,
} from '@/data/traffic';
import { mockCryptoVectorData, mockProfileSimilarity } from '@/data/crypto';
import { simulateNetworkDelay } from './client';

export async function fetchCurrentSecurityScore(): Promise<SecurityScore> {
  return simulateNetworkDelay(mockSecurityScore, 300);
}

export async function fetchComplianceFindings(): Promise<ComplianceFinding[]> {
  return simulateNetworkDelay(mockComplianceFindings, 350);
}

export async function fetchThreatFindings(): Promise<ThreatFinding[]> {
  return simulateNetworkDelay(mockThreatFindings, 300);
}

export async function fetchTrafficClassification(): Promise<TrafficClassification> {
  return simulateNetworkDelay(mockTrafficClassification, 400);
}

export async function fetchAnomalyResult(anomalousMode: boolean = false): Promise<AnomalyResult> {
  if (anomalousMode) {
    return simulateNetworkDelay(
      {
        score: 0.91,
        threshold: 0.72,
        status: 'ANOMALOUS',
        models: { autoencoder: 0.89, isolationForest: 0.93 },
        explanation:
          'High entropy MTU burst anomaly detected: Sustained high-throughput transfer deviating 4.2 sigma from normal baseline.',
      },
      300
    );
  }
  return simulateNetworkDelay(mockAnomalyResult, 300);
}

export async function fetchMetadataExposure(): Promise<MetadataExposure> {
  return simulateNetworkDelay(mockMetadataExposure, 350);
}

export async function fetchCryptoPosture() {
  return simulateNetworkDelay(
    {
      vectors: mockCryptoVectorData,
      similarity: mockProfileSimilarity,
    },
    300
  );
}

export interface PipelineStageEvent {
  stageId: string;
  stageName: string;
  engine: string;
  status: 'PENDING' | 'ACTIVE' | 'COMPLETED' | 'FAILED';
  log: string;
}

export const PIPELINE_STAGES: Array<{ id: string; name: string; engine: 'RULE' | 'ML' | 'RAG'; defaultMsg: string }> = [
  { id: '1', name: 'CAPTURE', engine: 'RULE', defaultMsg: 'Ingesting PCAP bitstream & raw frames...' },
  { id: '2', name: 'PARSE', engine: 'RULE', defaultMsg: 'Parsing IKEv2 grammars, ISAKMP payloads & ESP envelopes...' },
  { id: '3', name: 'CORRELATE', engine: 'RULE', defaultMsg: 'Reconstructing Child-SA pairs & bidirectional SPI tables...' },
  { id: '4', name: 'RFC ANALYSIS', engine: 'RULE', defaultMsg: 'Executing RFC 7296 / 8221 compliance test suite (24 rules)...' },
  { id: '5', name: 'CRYPTO ANALYSIS', engine: 'RULE', defaultMsg: 'Extracting key exchange vectors & quantum resistance metrics...' },
  { id: '6', name: 'TRAFFIC ML', engine: 'ML', defaultMsg: 'Running random-forest traffic classifier & autoencoder anomaly detector...' },
  { id: '7', name: 'RISK CORRELATION', engine: 'RULE', defaultMsg: 'Correlating rule violations with behavioral indicators...' },
  { id: '8', name: 'RAG ANALYSIS', engine: 'RAG', defaultMsg: 'Synthesizing evidence-grounded technical assessment & remediation...' },
  { id: '9', name: 'REPORT', engine: 'RAG', defaultMsg: 'Compiling executive & technical assessment dossiers...' },
];
