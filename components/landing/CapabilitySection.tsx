'use client';

import React from 'react';
import { 
  ShieldCheck, 
  Lock, 
  Binary, 
  FileText, 
  Check, 
  AlertTriangle,
  Flame,
  Fingerprint,
  Cpu
} from 'lucide-react';

interface EngineCapability {
  title: string;
  tag: string;
  rfcRef: string;
  icon: React.ElementType;
  items: { label: string; detail: string; status: 'ok' | 'warn' | 'info' }[];
  technicalNote: string;
}

const CAPABILITIES: EngineCapability[] = [
  {
    title: '1. RFC COMPLIANCE',
    tag: 'DETERMINISTIC RULE ENGINE',
    rfcRef: 'RFC 7296 / 4301 / 8221',
    icon: ShieldCheck,
    items: [
      { label: 'IKEv2 Negotiation', detail: 'SA_INIT, AUTH & CREATE_CHILD_SA state validation', status: 'ok' },
      { label: 'Crypto Proposal Validation', detail: 'Enforces compliant transforms (ENCR, PRF, INTEG, D-H)', status: 'ok' },
      { label: 'SA Lifetime Verification', detail: 'Flags excessive lifetimes > 7200s or volume overflows', status: 'warn' },
      { label: 'Replay Protection (ESN)', detail: 'Extended 64-bit sequence numbers & sliding window audit', status: 'ok' },
      { label: 'Perfect Forward Secrecy', detail: 'Validates fresh ephemeral DH rekeys on Child SAs', status: 'warn' },
      { label: 'Encapsulation Mode', detail: 'Strict Tunnel vs. Transport mode security boundary checks', status: 'ok' },
    ],
    technicalNote: 'Evaluates against 24 sovereign defense rule baselines without decrypting payloads.',
  },
  {
    title: '2. CRYPTOGRAPHIC POSTURE',
    tag: 'SUITE-B & QUANTUM READINESS',
    rfcRef: 'CNSA 2.0 / NIST SP 800-77',
    icon: Lock,
    items: [
      { label: 'Encryption Analysis', detail: 'Detects AES-256-GCM, AES-CBC, ChaCha20-Poly1305, 3DES', status: 'ok' },
      { label: 'Integrity & PRF Verification', detail: 'HMAC-SHA2-256/384/512 vs. broken legacy MD5/SHA1', status: 'ok' },
      { label: 'Diffie-Hellman Groups', detail: 'Group 19 (ECP-256), Group 20 (ECP-384), Group 14 (MODP-2048)', status: 'ok' },
      { label: 'Quantum Attack Surface', detail: 'Post-Quantum IPsec readiness assessment & hybrid IKE flags', status: 'info' },
      { label: 'Crypto Profile Scoring', detail: 'Mathematical posture grade from 0 to 100 based on primitives', status: 'ok' },
      { label: 'SPI & Nonce Entropy', detail: 'Monitors randomness of Security Parameter Indexes to prevent replay', status: 'ok' },
    ],
    technicalNote: 'Instantly surfaces deprecated algorithms, weak moduli, and unauthenticated ciphers.',
  },
  {
    title: '3. TRAFFIC INTELLIGENCE',
    tag: 'SIDE-CHANNEL ML CLASSIFIER',
    rfcRef: 'RFC 4303 §2.7 (TFC)',
    icon: Binary,
    items: [
      { label: 'Encrypted Traffic Classification', detail: 'Classifies VoIP, Video (H.264/RTP), HTTPS, DNS tunnels', status: 'ok' },
      { label: 'Packet-Size Fingerprinting', detail: 'Analyzes MTU/MSS framing and cumulative size histograms', status: 'ok' },
      { label: 'Timing & Inter-Arrival Cadence', detail: 'Detects 30Hz / 60Hz frame intervals leaking application state', status: 'warn' },
      { label: 'Burst & Entropy Profiling', detail: 'Differentiates interactive shells from bulk file transfers', status: 'ok' },
      { label: 'Metadata Leakage Alerts', detail: 'Surfaces missing Traffic Flow Confidentiality (TFC) padding', status: 'warn' },
      { label: 'Autonomous Anomaly Detection', detail: 'Identifies covert C2 channels masquerading as valid ESP tunnels', status: 'ok' },
    ],
    technicalNote: 'Passive wire telemetry analysis identifies cleartext protocol identity purely from envelope metadata.',
  },
  {
    title: '4. SECURITY REPORTING',
    tag: 'EVIDENCE-GROUNDED SYNTHESIS',
    rfcRef: 'RAG Grounded • ISO/IEC 27001',
    icon: FileText,
    items: [
      { label: 'Deterministic Risk Score', detail: 'Strict 0-100 composite index weighted across 6 security vectors', status: 'ok' },
      { label: 'MITRE Threat Matrix Mapping', detail: 'Correlates findings directly to T1573 (Encrypted Channel) & T1048', status: 'ok' },
      { label: 'AI Confidence Metric', detail: 'Quantified probability threshold for each ML traffic classification', status: 'ok' },
      { label: 'Actionable swanctl Diff', detail: 'Generates ready-to-deploy configuration patches to fix flaws', status: 'ok' },
      { label: 'Executive Briefing', detail: 'High-level cryptographic risk posture for command leadership', status: 'ok' },
      { label: 'Technical Proof Ledger', detail: 'Cryptographically timestamped audit log of all validated packets', status: 'ok' },
    ],
    technicalNote: 'RAG strictly synthesizes factual evidence discovered by analytical engines into formal reports.',
  },
];

export default function CapabilitySection() {
  return (
    <section id="capabilities" className="py-20 border-b border-sentinel-border/70 bg-sentinel-panel/30">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="mb-14">
          <div className="text-xs font-mono uppercase tracking-wider text-sentinel-copper mb-2 flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-sentinel-copper" />
            <span>Enterprise Security Engine Suite</span>
          </div>
          <h2 className="text-2xl sm:text-3xl lg:text-4xl font-bold tracking-tight text-sentinel-text">
            ONE PLATFORM. MULTIPLE SECURITY ENGINES.
          </h2>
          <p className="mt-3 text-sm text-sentinel-text-muted max-w-2xl font-mono">
            Modular, high-performance engines combine deterministic grammar parsing, cryptographic posture auditing, 
            machine learning traffic inference, and evidence-grounded reporting.
          </p>
        </div>

        {/* 4 Structured Technical Capability Panels */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {CAPABILITIES.map((cap, idx) => {
            const Icon = cap.icon;
            return (
              <div
                key={idx}
                className="rounded-xl border border-sentinel-border bg-sentinel-panel p-6 flex flex-col justify-between hover:border-sentinel-copper/40 transition-colors duration-200"
              >
                <div>
                  {/* Card Header */}
                  <div className="flex items-center justify-between pb-3 mb-4 border-b border-sentinel-border">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded border border-sentinel-copper/50 bg-sentinel-bg flex items-center justify-center text-sentinel-copper">
                        <Icon className="w-4 h-4 stroke-[1.8]" />
                      </div>
                      <div>
                        <h3 className="text-base font-bold text-sentinel-text tracking-wide">
                          {cap.title}
                        </h3>
                        <span className="text-[10px] font-mono text-sentinel-copper uppercase tracking-wider">
                          {cap.tag}
                        </span>
                      </div>
                    </div>
                    <span className="text-[10px] font-mono text-sentinel-text-muted px-2 py-0.5 rounded border border-sentinel-border bg-sentinel-bg">
                      {cap.rfcRef}
                    </span>
                  </div>

                  {/* List of Technical Features */}
                  <div className="space-y-3 my-4">
                    {cap.items.map((item, itemIdx) => (
                      <div
                        key={itemIdx}
                        className="flex items-start gap-2.5 text-xs font-mono"
                      >
                        <div className="mt-0.5">
                          {item.status === 'ok' && (
                            <Check className="w-3.5 h-3.5 text-sentinel-mint" />
                          )}
                          {item.status === 'warn' && (
                            <AlertTriangle className="w-3.5 h-3.5 text-sentinel-warning" />
                          )}
                          {item.status === 'info' && (
                            <span className="inline-block w-3.5 h-3.5 rounded-full border border-sentinel-info text-[9px] text-center leading-3 text-sentinel-info">
                              i
                            </span>
                          )}
                        </div>
                        <div className="flex-1">
                          <span className="font-semibold text-sentinel-text mr-1.5">
                            {item.label}:
                          </span>
                          <span className="text-sentinel-text-muted font-normal">
                            {item.detail}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Card Technical Note Footer */}
                <div className="mt-5 pt-3 border-t border-sentinel-border/70 text-[11px] font-mono text-sentinel-text-muted flex items-center justify-between">
                  <span>{cap.technicalNote}</span>
                  <span className="text-sentinel-copper font-bold">● ONLINE</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
