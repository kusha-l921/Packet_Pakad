export interface CryptoVectorMetric {
  parameter: string;
  observedValue: string;
  normalizedScore: number; // 0 - 100
  nistLevel: string;
  securityBits: number;
  quantumResistant: boolean;
  standardCompliance: string;
}

export const mockCryptoVectorData: CryptoVectorMetric[] = [
  {
    parameter: 'Symmetric Cipher',
    observedValue: 'AES-256-GCM',
    normalizedScore: 98,
    nistLevel: 'Category 5',
    securityBits: 256,
    quantumResistant: true, // Grover search requires AES-256
    standardCompliance: 'RFC 8221 / CNSA Suite',
  },
  {
    parameter: 'Integrity Verification',
    observedValue: 'AEAD 128-bit ICV',
    normalizedScore: 95,
    nistLevel: 'High',
    securityBits: 128,
    quantumResistant: true,
    standardCompliance: 'RFC 4106 / NIST SP 800-38D',
  },
  {
    parameter: 'Key Exchange (IKE)',
    observedValue: 'ECDH Group 19 (NIST P-256)',
    normalizedScore: 82,
    nistLevel: 'Category 1',
    securityBits: 128,
    quantumResistant: false, // Vulnerable to Shor algorithm
    standardCompliance: 'RFC 5903',
  },
  {
    parameter: 'Pseudorandom Function',
    observedValue: 'PRF-HMAC-SHA2-256',
    normalizedScore: 92,
    nistLevel: 'High',
    securityBits: 256,
    quantumResistant: true,
    standardCompliance: 'RFC 4868',
  },
  {
    parameter: 'Forward Secrecy (PFS)',
    observedValue: 'Active for IKE SA (Omitted on Rekey)',
    normalizedScore: 68,
    nistLevel: 'Medium',
    securityBits: 128,
    quantumResistant: false,
    standardCompliance: 'RFC 7296 (Degraded on Rekey)',
  },
  {
    parameter: 'Anti-Replay Mechanism',
    observedValue: '64-bit Extended Sequence (ESN)',
    normalizedScore: 100,
    nistLevel: 'Maximum',
    securityBits: 64,
    quantumResistant: true,
    standardCompliance: 'RFC 4303 Section 3.3.3',
  },
];

export const mockProfileSimilarity = {
  observedLabel: 'AES-256-GCM / SHA-256 / DH19 / PFS-ENABLED',
  profiles: [
    {
      name: 'Modern Classical',
      matchPercentage: 92,
      description: 'AEAD ciphers with elliptic-curve Diffie-Hellman (NIST P-256 or Curve25519) and strict integrity. Highly resilient to non-quantum adversaries.',
      status: 'PRIMARY MATCH',
      color: '#C47A52',
    },
    {
      name: 'PQC Transitional Hybrid',
      matchPercentage: 48,
      description: 'Post-Quantum hybrid key exchange (e.g. ML-KEM-768 combined with X25519) to mitigate Store-Now-Decrypt-Later threats.',
      status: 'TRANSITIONAL TARGET',
      color: '#8FB8A8',
    },
    {
      name: 'Legacy Deprecated',
      matchPercentage: 21,
      description: 'CBC-mode ciphers, HMAC-SHA1/MD5, and MODP groups under 2048 bits. Non-compliant with current sovereign defense criteria.',
      status: 'DEVIATION',
      color: '#D7A84D',
    },
  ],
};
