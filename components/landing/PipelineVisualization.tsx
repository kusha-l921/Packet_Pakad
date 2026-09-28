'use client';

import React, { useState } from 'react';
import { 
  Radio, 
  GitMerge, 
  KeyRound, 
  FileCheck2, 
  Activity, 
  FileSpreadsheet,
  ArrowRight,
  ShieldCheck,
  CheckCircle2
} from 'lucide-react';

interface Stage {
  id: string;
  name: string;
  title: string;
  description: string;
  metadata: string;
  rules: string[];
  icon: React.ElementType;
}

const STAGES: Stage[] = [
  {
    id: 'capture',
    name: '01. CAPTURE',
    title: 'Raw Frame Ingestion',
    description: 'IKE, ESP, AH and raw network frames ingested via live AF_PACKET or PCAP stream.',
    metadata: 'UDP 500 / 4500 • Proto 50/51',
    rules: ['Promiscuous ring-buffer', 'Kernel bypass zero-copy', 'Timestamp microsecond precision'],
    icon: Radio,
  },
  {
    id: 'reconstruct',
    name: '02. RECONSTRUCT',
    title: 'Session Dissection',
    description: 'Correlate IKE_SA_INIT, IKE_AUTH, and Child SA pairs using SPI and nonce maps.',
    metadata: 'SPI In / Out • Nonce Binding',
    rules: ['IKEv2 state tracking', 'Parent-Child SA linking', 'Multi-gateway mesh mapping'],
    icon: GitMerge,
  },
  {
    id: 'identify',
    name: '03. IDENTIFY',
    title: 'Cryptographic Grammar',
    description: 'Extract cipher suites, PRF, DH group proposals, PFS flags, and tunnel encapsulation.',
    metadata: 'AES-256-GCM • DH Group 19',
    rules: ['Proposal parsing (ENCR, INTEG)', 'Key exchange validation', 'NAT-T marker detection'],
    icon: KeyRound,
  },
  {
    id: 'assess',
    name: '04. ASSESS',
    title: 'RFC & Hardening Audit',
    description: 'Automated RFC 7296, 4301, 8221 compliance checks and sovereign defense baselines.',
    metadata: '24 Rules • Anti-Replay 64-bit',
    rules: ['SA lifetime verification', 'PFS rekey payload audit', 'Extended Sequence Numbers (ESN)'],
    icon: FileCheck2,
  },
  {
    id: 'correlate',
    name: '05. CORRELATE',
    title: 'Traffic Intelligence',
    description: 'Correlate timing distributions, packet burst sizes, and side-channel metadata leakages.',
    metadata: 'Entropy • ML Inference 94.2%',
    rules: ['Video cadence fingerprinting', 'Burst entropy profiling', 'TFC padding absence alerts'],
    icon: Activity,
  },
  {
    id: 'report',
    name: '06. REPORT',
    title: 'Grounded Evidence Report',
    description: 'Generate audit-ready executive summaries and technical remediation config patches.',
    metadata: 'RAG Grounded • RFC Anchors',
    rules: ['Deterministic findings synthesis', 'swanctl.conf remediation diff', 'Formal audit ledger'],
    icon: FileSpreadsheet,
  },
];

export default function PipelineVisualization() {
  const [activeStage, setActiveStage] = useState<number>(2); // Default to Identify/Assess

  return (
    <section id="pipeline" className="py-20 border-b border-sentinel-border/70 bg-sentinel-bg">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="flex flex-col md:flex-row md:items-end justify-between mb-12">
          <div>
            <div className="text-xs font-mono uppercase tracking-wider text-sentinel-copper mb-2 flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-sentinel-copper" />
              <span>Multi-Stage Dissection Architecture</span>
            </div>
            <h2 className="text-2xl sm:text-3xl lg:text-4xl font-bold tracking-tight text-sentinel-text">
              FROM PACKETS TO SECURITY INTELLIGENCE
            </h2>
          </div>
          <p className="mt-3 md:mt-0 text-xs sm:text-sm text-sentinel-text-muted max-w-md font-mono">
            Every network frame traverses a rigorous 6-stage deterministic analytical engine before executive reporting.
          </p>
        </div>

        {/* Horizontal Technical Flow Steps */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-8">
          {STAGES.map((stage, idx) => {
            const Icon = stage.icon;
            const isSelected = activeStage === idx;
            return (
              <button
                key={stage.id}
                onClick={() => setActiveStage(idx)}
                className={`text-left p-4 rounded-lg border transition-all duration-200 relative flex flex-col justify-between min-h-[160px] ${
                  isSelected
                    ? 'border-sentinel-copper bg-sentinel-panel shadow-md shadow-sentinel-copper/10'
                    : 'border-sentinel-border bg-sentinel-panel/40 hover:border-sentinel-border/90 hover:bg-sentinel-panel/80'
                }`}
              >
                {/* Active indicator bar */}
                {isSelected && (
                  <div className="absolute top-0 left-0 right-0 h-0.5 bg-sentinel-copper rounded-t" />
                )}

                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-[10px] font-mono tracking-wider text-sentinel-text-muted">
                      {stage.name}
                    </span>
                    <Icon
                      className={`w-4 h-4 ${
                        isSelected ? 'text-sentinel-copper' : 'text-sentinel-text-muted'
                      }`}
                    />
                  </div>
                  <h3 className="text-sm font-semibold text-sentinel-text mb-1">
                    {stage.title}
                  </h3>
                  <p className="text-[11px] text-sentinel-text-muted leading-snug line-clamp-2">
                    {stage.description}
                  </p>
                </div>

                <div className="mt-3 pt-2 border-t border-sentinel-border/50 text-[10px] font-mono text-sentinel-copper truncate">
                  {stage.metadata}
                </div>
              </button>
            );
          })}
        </div>

        {/* Detailed Stage Deep-Dive Card */}
        <div className="p-6 rounded-xl border border-sentinel-border bg-sentinel-panel">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
            <div className="flex-1">
              <div className="flex items-center gap-3 mb-2 font-mono text-xs">
                <span className="text-sentinel-copper font-bold uppercase tracking-wider">
                  {STAGES[activeStage].name} • {STAGES[activeStage].title}
                </span>
                <span className="text-sentinel-mint bg-sentinel-mint/10 px-2 py-0.5 rounded text-[10px]">
                  VERIFIED RFC STANDARD
                </span>
              </div>
              <p className="text-sm text-sentinel-text mb-4 max-w-2xl leading-relaxed">
                {STAGES[activeStage].description}
              </p>
              <div className="flex flex-wrap gap-2 text-xs font-mono">
                {STAGES[activeStage].rules.map((rule, i) => (
                  <span
                    key={i}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded border border-sentinel-border bg-sentinel-bg text-sentinel-text-muted text-[11px]"
                  >
                    <CheckCircle2 className="w-3 h-3 text-sentinel-mint" />
                    <span>{rule}</span>
                  </span>
                ))}
              </div>
            </div>

            {/* Stage Telemetry Snippet */}
            <div className="w-full lg:w-80 p-3.5 rounded-lg border border-sentinel-border bg-[#0B0C0D] font-mono text-[11px] text-sentinel-text-muted">
              <div className="text-[10px] text-sentinel-copper uppercase font-semibold border-b border-sentinel-border/60 pb-1 mb-2">
                ACTIVE STAGE TELEMETRY
              </div>
              <div className="space-y-1">
                <div className="flex justify-between">
                  <span>Engine:</span>
                  <span className="text-sentinel-text">SovereignNet v4.19</span>
                </div>
                <div className="flex justify-between">
                  <span>Latency:</span>
                  <span className="text-sentinel-mint">&lt; 14ms (Zero-Copy)</span>
                </div>
                <div className="flex justify-between">
                  <span>Standard:</span>
                  <span className="text-sentinel-copper font-bold">NTRO-26160-C3</span>
                </div>
                <div className="flex justify-between">
                  <span>Replay Window:</span>
                  <span className="text-sentinel-text">64-pkt ESN</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
