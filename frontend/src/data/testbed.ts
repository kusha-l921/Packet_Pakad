import { TestbedConfiguration } from '@/types';

// Predefined IKE Proposal Suites (Exact match to terminal application screenshot)
export interface PredefinedIkeSuite {
  id: number;
  label: string;
  category: 'PQC-HYBRID' | 'CLASSICAL' | 'CLASSICAL-CBC' | 'BROKEN-INSECURE';
  ike: string;
  encr: string;
  prf: string;
  integ: string;
  primaryKe: string;
  additionalKe: string;
  rounds: number;
  pqc: boolean;
}

export const predefinedIkeSuites: PredefinedIkeSuite[] = [
  {
    id: 1,
    label: '[ 1] Post-Quantum Hybrid: AES-256-GCM + SHA-384 + ECP-384 + ML-KEM-768',
    category: 'PQC-HYBRID',
    ike: 'aes256gcm16-prfsha384-ecp384-ke1_mlkem768,aes256gcm16-prfsha384-ecp384',
    encr: 'ENCR_AES_GCM_16 (256-bit)',
    prf: 'PRF_HMAC_SHA2_384',
    integ: 'NONE (AEAD Implicit)',
    primaryKe: 'ECP-384 (NIST P-384 / secp384r1, Group 20)',
    additionalKe: 'ML-KEM-768 (Kyber-768, ID 36)',
    rounds: 2,
    pqc: true,
  },
  {
    id: 2,
    label: '[ 2] Post-Quantum Hybrid: AES-256-GCM + SHA-384 + ECP-384 + ML-KEM-1024',
    category: 'PQC-HYBRID',
    ike: 'aes256gcm16-prfsha384-ecp384-ke1_mlkem1024,aes256gcm16-prfsha384-ecp384',
    encr: 'ENCR_AES_GCM_16 (256-bit)',
    prf: 'PRF_HMAC_SHA2_384',
    integ: 'NONE (AEAD Implicit)',
    primaryKe: 'ECP-384 (NIST P-384 / secp384r1, Group 20)',
    additionalKe: 'ML-KEM-1024 (Kyber-1024, ID 37)',
    rounds: 2,
    pqc: true,
  },
  {
    id: 3,
    label: '[ 3] Post-Quantum Hybrid: AES-256-GCM + SHA-256 + Curve25519 + ML-KEM-768',
    category: 'PQC-HYBRID',
    ike: 'aes256gcm16-prfsha256-curve25519-ke1_mlkem768,aes256gcm16-prfsha256-curve25519',
    encr: 'ENCR_AES_GCM_16 (256-bit)',
    prf: 'PRF_HMAC_SHA2_256',
    integ: 'NONE (AEAD Implicit)',
    primaryKe: 'Curve25519 (X25519, Group 31)',
    additionalKe: 'ML-KEM-768 (Kyber-768, ID 36)',
    rounds: 2,
    pqc: true,
  },
  {
    id: 4,
    label: '[ 4] Post-Quantum Hybrid: AES-128-GCM + SHA-256 + Curve25519 + ML-KEM-512',
    category: 'PQC-HYBRID',
    ike: 'aes128gcm16-prfsha256-curve25519-ke1_mlkem512,aes128gcm16-prfsha256-curve25519',
    encr: 'ENCR_AES_GCM_16 (128-bit)',
    prf: 'PRF_HMAC_SHA2_256',
    integ: 'NONE (AEAD Implicit)',
    primaryKe: 'Curve25519 (X25519, Group 31)',
    additionalKe: 'ML-KEM-512 (Kyber-512, ID 35)',
    rounds: 2,
    pqc: true,
  },
  {
    id: 5,
    label: '[ 5] Post-Quantum Hybrid: AES-256-GCM + SHA-384 + ECP-384 + FrodoKEM-976',
    category: 'PQC-HYBRID',
    ike: 'aes256gcm16-prfsha384-ecp384-ke1_frodokem976shake,aes256gcm16-prfsha384-ecp384',
    encr: 'ENCR_AES_GCM_16 (256-bit)',
    prf: 'PRF_HMAC_SHA2_384',
    integ: 'NONE (AEAD Implicit)',
    primaryKe: 'ECP-384 (NIST P-384 / secp384r1, Group 20)',
    additionalKe: 'FrodoKEM-976-AES (SHAKE, ID 39)',
    rounds: 2,
    pqc: true,
  },
  {
    id: 6,
    label: '[ 6] High-Security Classical: AES-256-GCM + SHA-384 + ECP-384',
    category: 'CLASSICAL',
    ike: 'aes256gcm16-prfsha384-ecp384',
    encr: 'ENCR_AES_GCM_16 (256-bit)',
    prf: 'PRF_HMAC_SHA2_384',
    integ: 'NONE (AEAD Implicit)',
    primaryKe: 'ECP-384 (NIST P-384 / secp384r1, Group 20)',
    additionalKe: 'None',
    rounds: 1,
    pqc: false,
  },
  {
    id: 7,
    label: '[ 7] Standard Classical: AES-128-GCM + SHA-256 + ECP-256',
    category: 'CLASSICAL',
    ike: 'aes128gcm16-prfsha256-ecp256',
    encr: 'ENCR_AES_GCM_16 (128-bit)',
    prf: 'PRF_HMAC_SHA2_256',
    integ: 'NONE (AEAD Implicit)',
    primaryKe: 'ECP-256 (NIST P-256 / secp256r1, Group 19)',
    additionalKe: 'None',
    rounds: 1,
    pqc: false,
  },
  {
    id: 8,
    label: '[ 8] Fast Classical: AES-256-GCM + SHA-256 + Curve25519',
    category: 'CLASSICAL',
    ike: 'aes256gcm16-prfsha256-curve25519',
    encr: 'ENCR_AES_GCM_16 (256-bit)',
    prf: 'PRF_HMAC_SHA2_256',
    integ: 'NONE (AEAD Implicit)',
    primaryKe: 'Curve25519 (X25519, Group 31)',
    additionalKe: 'None',
    rounds: 1,
    pqc: false,
  },
  {
    id: 9,
    label: '[ 9] Enterprise Classical: AES-256-CBC + SHA-384 + MODP-3072',
    category: 'CLASSICAL-CBC',
    ike: 'aes256-sha384-modp3072',
    encr: 'ENCR_AES_CBC (256-bit)',
    prf: 'PRF_HMAC_SHA2_384',
    integ: 'AUTH_HMAC_SHA2_384_192',
    primaryKe: '3072-bit MODP Group (Group 15)',
    additionalKe: 'None',
    rounds: 1,
    pqc: false,
  },
  {
    id: 10,
    label: '[10] Legacy Classical: AES-256-CBC + SHA-256 + MODP-2048',
    category: 'CLASSICAL-CBC',
    ike: 'aes256-sha256-modp2048',
    encr: 'ENCR_AES_CBC (256-bit)',
    prf: 'PRF_HMAC_SHA2_256',
    integ: 'AUTH_HMAC_SHA2_256_128',
    primaryKe: '2048-bit MODP Group (Group 14)',
    additionalKe: 'None',
    rounds: 1,
    pqc: false,
  },
  {
    id: 11,
    label: '[11] Insecure Legacy: 3DES-CBC + HMAC-MD5 + MODP-1024 (Vulnerable)',
    category: 'BROKEN-INSECURE',
    ike: '3des-md5-modp1024',
    encr: 'ENCR_3DES (192-bit, Deprecated / Broken)',
    prf: 'PRF_HMAC_MD5 (Insecure Collision Attacks)',
    integ: 'AUTH_HMAC_MD5_96 (Insecure / Prohibited)',
    primaryKe: '1024-bit MODP Group (Group 2, Vulnerable Logjam)',
    additionalKe: 'None',
    rounds: 1,
    pqc: false,
  },
];

// Predefined ESP Child SA Proposal Suites (Matching testbed_generator.ESP_OPTIONS)
export interface PredefinedEspSuite {
  id: number;
  label: string;
  esp: string;
  encr: string;
  integ: string;
  pfs: string;
  esn: string;
}

export const predefinedEspSuites: PredefinedEspSuite[] = [
  {
    id: 1,
    label: '[1] AES-256-GCM (No PFS)',
    esp: 'aes256gcm16',
    encr: 'ENCR_AES_GCM_16 (256-bit)',
    integ: 'NONE (AEAD Implicit)',
    pfs: 'None (No PFS)',
    esn: '64-bit Extended Sequence Numbers',
  },
  {
    id: 2,
    label: '[2] AES-128-GCM (No PFS)',
    esp: 'aes128gcm16',
    encr: 'ENCR_AES_GCM_16 (128-bit)',
    integ: 'NONE (AEAD Implicit)',
    pfs: 'None (No PFS)',
    esn: '64-bit Extended Sequence Numbers',
  },
  {
    id: 3,
    label: '[3] AES-256-GCM + ECP-384 (PFS)',
    esp: 'aes256gcm16-ecp384',
    encr: 'ENCR_AES_GCM_16 (256-bit)',
    integ: 'NONE (AEAD Implicit)',
    pfs: 'ECP-384 (Group 20)',
    esn: '64-bit Extended Sequence Numbers',
  },
  {
    id: 4,
    label: '[4] AES-256-GCM + Curve25519 (PFS)',
    esp: 'aes256gcm16-curve25519',
    encr: 'ENCR_AES_GCM_16 (256-bit)',
    integ: 'NONE (AEAD Implicit)',
    pfs: 'Curve25519 (Group 31)',
    esn: '64-bit Extended Sequence Numbers',
  },
  {
    id: 5,
    label: '[5] AES-256-CBC + HMAC-SHA256 (No PFS)',
    esp: 'aes256-sha256',
    encr: 'ENCR_AES_CBC (256-bit)',
    integ: 'AUTH_HMAC_SHA2_256_128',
    pfs: 'None (No PFS)',
    esn: '32-bit Sequential Numbers',
  },
  {
    id: 6,
    label: '[6] 3DES-CBC + HMAC-MD5 (Insecure / Deprecated)',
    esp: '3des-md5',
    encr: 'ENCR_3DES (192-bit)',
    integ: 'AUTH_HMAC_MD5_96 (Insecure)',
    pfs: 'None (No PFS)',
    esn: '32-bit Sequential Numbers',
  },
];

// Granular IANA IKEv2 Transform Parameters (Derived from ikeV2IDs.py)
export const ikev2EncryptionTransforms = [
  { id: '20', name: 'ENCR_AES_GCM_16 (AES-256/128-GCM, 16-octet ICV - AEAD)' },
  { id: '19', name: 'ENCR_AES_GCM_12 (12-octet ICV)' },
  { id: '18', name: 'ENCR_AES_GCM_8 (8-octet ICV)' },
  { id: '28', name: 'ENCR_CHACHA20_POLY1305 (ChaCha20-Poly1305 - AEAD)' },
  { id: '12', name: 'ENCR_AES_CBC (CBC Mode - 128/256-bit)' },
  { id: '13', name: 'ENCR_AES_CTR (Counter Mode)' },
  { id: '14', name: 'ENCR_AES_CCM_8' },
  { id: '15', name: 'ENCR_AES_CCM_12' },
  { id: '16', name: 'ENCR_AES_CCM_16' },
  { id: '23', name: 'ENCR_CAMELLIA_CBC' },
  { id: '3', name: 'ENCR_3DES (Triple-DES, Legacy Deprecated)' },
  { id: '11', name: 'ENCR_NULL (Unencrypted ESP - Diagnostic)' },
];

export const ikev2PrfTransforms = [
  { id: '5', name: 'PRF_HMAC_SHA2_256 (SHA-256 Standard)' },
  { id: '6', name: 'PRF_HMAC_SHA2_384 (SHA-384 High Security)' },
  { id: '7', name: 'PRF_HMAC_SHA2_512 (SHA-512 Maximum)' },
  { id: '4', name: 'PRF_AES128_XCBC (AES-XCBC)' },
  { id: '8', name: 'PRF_AES128_CMAC (AES-CMAC)' },
  { id: '2', name: 'PRF_HMAC_SHA1 (SHA-1 Legacy)' },
  { id: '1', name: 'PRF_HMAC_MD5 (MD5 Insecure - Testing Only)' },
];

export const ikev2IntegrityTransforms = [
  { id: '0', name: 'NONE (Implicit in AEAD Ciphers like AES-GCM & ChaCha20)' },
  { id: '12', name: 'AUTH_HMAC_SHA2_256_128 (HMAC-SHA-256)' },
  { id: '13', name: 'AUTH_HMAC_SHA2_384_192 (HMAC-SHA-384)' },
  { id: '14', name: 'AUTH_HMAC_SHA2_512_256 (HMAC-SHA-512)' },
  { id: '5', name: 'AUTH_AES_XCBC_96 (AES-XCBC-96)' },
  { id: '8', name: 'AUTH_AES_CMAC_96 (AES-CMAC-96)' },
  { id: '9', name: 'AUTH_AES_128_GMAC (AES-128-GMAC)' },
  { id: '11', name: 'AUTH_AES_256_GMAC (AES-256-GMAC)' },
  { id: '2', name: 'AUTH_HMAC_SHA1_96 (SHA-1 Legacy Deprecated)' },
  { id: '1', name: 'AUTH_HMAC_MD5_96 (MD5 Insecure)' },
];

export const ikev2KeyExchangeTransforms = [
  { id: '20', name: 'Group 20: 384-bit Random ECP (NIST P-384 / secp384r1)', type: 'Classical' },
  { id: '31', name: 'Group 31: Curve25519 (X25519 Modern Fast ECDH)', type: 'Classical' },
  { id: '19', name: 'Group 19: 256-bit Random ECP (NIST P-256 / secp256r1)', type: 'Classical' },
  { id: '21', name: 'Group 21: 521-bit Random ECP (NIST P-521 / secp521r1)', type: 'Classical' },
  { id: '32', name: 'Group 32: Curve448 (X448 High Security ECDH)', type: 'Classical' },
  { id: '15', name: 'Group 15: 3072-bit MODP Group (High Classical)', type: 'Classical' },
  { id: '14', name: 'Group 14: 2048-bit MODP Group (Standard Classical)', type: 'Classical' },
  { id: '16', name: 'Group 16: 4096-bit MODP Group (Maximum Classical)', type: 'Classical' },
  { id: '36', name: 'ML-KEM-768 (Kyber-768 - NIST FIPS 203)', type: 'PQC' },
  { id: '37', name: 'ML-KEM-1024 (Kyber-1024 - NIST FIPS 203)', type: 'PQC' },
  { id: '35', name: 'ML-KEM-512 (Kyber-512 - NIST FIPS 203)', type: 'PQC' },
  { id: '39', name: 'FrodoKEM-976-AES (NIST Round 3 PQC)', type: 'PQC' },
  { id: '38', name: 'FrodoKEM-640-AES (NIST Round 3 PQC)', type: 'PQC' },
  { id: '40', name: 'FrodoKEM-1344-AES (NIST Round 3 PQC)', type: 'PQC' },
];

export const ikev2EsnTransforms = [
  { id: '1', name: 'ESN: 64-bit Extended Sequence Numbers (Anti-Replay Recommended)' },
  { id: '0', name: 'No ESN: Standard 32-bit Sequence Numbers' },
  { id: '2', name: '32-bit Unspecified Numbers' },
];

export const defaultTestbedConfig: TestbedConfiguration = {
  ikeVersion: 'IKEv2',
  mode: 'Tunnel',
  encryption: 'AES-GCM',
  dhGroup: '20',
  pfs: true,
  ipVersion: 'IPv4',
  trafficType: 'Video',
  packetRate: 500,
  expectedSecurity: 'STRONG',
  profileCategory: 'POST-QUANTUM HYBRID',
  ikeProposalSuite: 1,
  espProposalSuite: 3,
  keyExchangeRounds: 2,
  primaryKeyExchange: '20',
  additionalKeyExchange1: '36',
  additionalKeyExchange2: '39',
  childSaCount: 1,
  saInitTransforms: {
    encr: '20',
    prf: '6',
    integ: '0',
    ke: '20',
  },
  childSaTransforms: {
    encr: '20',
    integ: '0',
    dh: '20',
    esn: '1',
  },
};

export const testbedPresets = [
  {
    name: 'PQC Suite 1 (ML-KEM-768 + ECP-384)',
    description: 'Post-Quantum hybrid key exchange combining ML-KEM-768 with classical ECDH ECP-384.',
    config: {
      ikeVersion: 'IKEv2' as const,
      mode: 'Tunnel' as const,
      encryption: 'AES-GCM' as const,
      dhGroup: '20' as const,
      pfs: true,
      ipVersion: 'IPv4' as const,
      trafficType: 'Video' as const,
      expectedSecurity: 'STRONG' as const,
      profileCategory: 'POST-QUANTUM HYBRID',
      ikeProposalSuite: 1,
      espProposalSuite: 3,
      keyExchangeRounds: 2,
      childSaCount: 1,
    },
  },
  {
    name: 'PQC Suite 3 (ML-KEM-768 + X25519)',
    description: 'Modern high-performance hybrid suite with Curve25519 and ML-KEM-768.',
    config: {
      ikeVersion: 'IKEv2' as const,
      mode: 'Tunnel' as const,
      encryption: 'AES-GCM' as const,
      dhGroup: '31' as const,
      pfs: true,
      ipVersion: 'IPv4' as const,
      trafficType: 'VoIP' as const,
      expectedSecurity: 'STRONG' as const,
      profileCategory: 'POST-QUANTUM HYBRID',
      ikeProposalSuite: 3,
      espProposalSuite: 4,
      keyExchangeRounds: 2,
      childSaCount: 2,
    },
  },
  {
    name: 'Classical RFC 8247 Standard',
    description: 'CNSA classical suite with AES-256-GCM, PRF-SHA384, and ECP-384 (1 Key Exchange).',
    config: {
      ikeVersion: 'IKEv2' as const,
      mode: 'Tunnel' as const,
      encryption: 'AES-GCM' as const,
      dhGroup: '20' as const,
      pfs: true,
      ipVersion: 'IPv4' as const,
      trafficType: 'Web' as const,
      expectedSecurity: 'STRONG' as const,
      profileCategory: 'MODERN CLASSICAL',
      ikeProposalSuite: 6,
      espProposalSuite: 3,
      keyExchangeRounds: 1,
      childSaCount: 1,
    },
  },
  {
    name: 'Legacy MODP-2048 Lab',
    description: 'Legacy configuration with AES-256-CBC and MODP-2048 Diffie-Hellman.',
    config: {
      ikeVersion: 'IKEv2' as const,
      mode: 'Tunnel' as const,
      encryption: 'AES-256' as const,
      dhGroup: '14' as const,
      pfs: false,
      ipVersion: 'IPv4' as const,
      trafficType: 'Web' as const,
      expectedSecurity: 'ACCEPTABLE' as const,
      profileCategory: 'LEGACY TRANSITIONAL',
      ikeProposalSuite: 10,
      espProposalSuite: 5,
      keyExchangeRounds: 1,
      childSaCount: 1,
    },
  },
  {
    name: 'Broken Crypto Insecurity Lab',
    description: 'Intentionally broken legacy suite with 3DES-CBC, MD5, and MODP-1024 to trigger RFC compliance warnings.',
    config: {
      ikeVersion: 'IKEv2' as const,
      mode: 'Tunnel' as const,
      encryption: '3DES-CBC' as const,
      dhGroup: '2' as const,
      pfs: false,
      ipVersion: 'IPv4' as const,
      trafficType: 'Web' as const,
      expectedSecurity: 'WEAK' as const,
      profileCategory: 'BROKEN / HIGH VULNERABILITY',
      ikeProposalSuite: 11,
      espProposalSuite: 6,
      keyExchangeRounds: 1,
      childSaCount: 1,
    },
  },
];

export const testbedDeploymentStages = [
  { id: '1', name: 'CONFIGURING', message: 'Generating cryptographic security policies and tunnel configurations...' },
  { id: '2', name: 'GATEWAYS READY', message: 'Verifying gateway connectivity on HQ and Branch endpoints...' },
  { id: '3', name: 'AUTHENTICATING', message: 'Negotiating secure authentication and key exchange handshakes...' },
  { id: '4', name: 'TUNNELS ESTABLISHED', message: 'Installing encrypted data tunnels and activating anti-replay policies...' },
  { id: '5', name: 'TRAFFIC ACTIVE', message: 'Synthetic traffic generator online and packet telemetry active.' },
];

