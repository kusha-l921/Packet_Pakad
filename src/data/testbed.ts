import { TestbedConfiguration } from '@/types';

export const defaultTestbedConfig: TestbedConfiguration = {
  ikeVersion: 'IKEv2',
  mode: 'Tunnel',
  encryption: 'AES-GCM',
  authentication: 'ECDSA',
  dhGroup: '19',
  pfs: true,
  ipVersion: 'IPv4',
  trafficType: 'Video',
  packetRate: 500,
  expectedSecurity: 'STRONG',
  profileCategory: 'MODERN CLASSICAL',
};

export const testbedPresets = [
  {
    name: 'NTRO Sovereign Standard',
    description: 'Complies with government standard for secure inter-agency border gateways.',
    config: {
      ikeVersion: 'IKEv2' as const,
      mode: 'Tunnel' as const,
      encryption: 'AES-GCM' as const,
      authentication: 'ECDSA' as const,
      dhGroup: '19' as const,
      pfs: true,
      ipVersion: 'IPv4' as const,
      trafficType: 'Video' as const,
      expectedSecurity: 'STRONG' as const,
      profileCategory: 'MODERN CLASSICAL',
    },
  },
  {
    name: 'Legacy Interop Lab',
    description: 'Simulates older legacy equipment with CBC mode and MODP Diffie-Hellman.',
    config: {
      ikeVersion: 'IKEv2' as const,
      mode: 'Tunnel' as const,
      encryption: 'AES-CBC-HMAC' as const,
      authentication: 'PSK' as const,
      dhGroup: '14' as const,
      pfs: false,
      ipVersion: 'IPv4' as const,
      trafficType: 'Web' as const,
      expectedSecurity: 'ACCEPTABLE' as const,
      profileCategory: 'LEGACY TRANSITIONAL',
    },
  },
  {
    name: 'Zero Trust High-Speed',
    description: 'ChaCha20-Poly1305 with Curve25519 (Group 31) for rapid packet processing.',
    config: {
      ikeVersion: 'IKEv2' as const,
      mode: 'Tunnel' as const,
      encryption: 'AES-GCM' as const,
      authentication: 'ECDSA' as const,
      dhGroup: '31' as const,
      pfs: true,
      ipVersion: 'IPv6' as const,
      trafficType: 'VoIP' as const,
      expectedSecurity: 'STRONG' as const,
      profileCategory: 'HIGH ASSURANCE',
    },
  },
  {
    name: 'PQC Hybrid Candidate',
    description: 'Post-Quantum key exchange testbed combining ML-KEM with classical ECDH.',
    config: {
      ikeVersion: 'IKEv2' as const,
      mode: 'Tunnel' as const,
      encryption: 'AES-GCM' as const,
      authentication: 'ECDSA' as const,
      dhGroup: '21' as const,
      pfs: true,
      ipVersion: 'IPv6' as const,
      trafficType: 'Email' as const,
      expectedSecurity: 'STRONG' as const,
      profileCategory: 'POST-QUANTUM HYBRID',
    },
  },
];

export const testbedDeploymentStages = [
  { id: '1', name: 'CONFIGURING', message: 'Compiling strongSwan ipsec.conf and swanctl.conf profile...' },
  { id: '2', name: 'DEPLOYING', message: 'Spawning isolated Linux network namespaces (ns_client, ns_responder)...' },
  { id: '3', name: 'ESTABLISHING IKE', message: 'Triggering IKEv2 IKE_SA_INIT and mutual X.509 ECDSA authentication...' },
  { id: '4', name: 'CREATING CHILD SA', message: 'Negotiating ESP Child SA policies and deriving ephemeral session keys...' },
  { id: '5', name: 'READY', message: 'Synthetic traffic generator online and PCAP ingestion ring-buffer ready.' },
];
