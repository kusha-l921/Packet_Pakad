'use client';

import React, { useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { AppShell } from '@/components/layout/AppShell';
import { mockSessions } from '@/data/sessions';
import { StatusBadge } from '@/components/common/StatusBadge';
import { TechnicalField } from '@/components/common/TechnicalField';
import { motion } from 'framer-motion';
import {
  Shield,
  ArrowLeft,
  Key,
  Clock,
  Layers,
  Activity,
  AlertTriangle,
  CheckCircle2,
  FileText,
  Lock,
  Download,
  Share2,
  ExternalLink,
  ChevronDown,
  Terminal,
} from 'lucide-react';
import Link from 'next/link';

export default function SessionAnalysisPage() {
  const params = useParams();
  const router = useRouter();
  const sessionId = (params?.id as string) || 'IPSEC-00421';

  // Find or fallback to primary session
  const session =
    mockSessions.find((s) => s.id.toLowerCase() === sessionId.toLowerCase()) ||
    mockSessions[0];

  const [activeTimelineStep, setActiveTimelineStep] = useState<number>(2); // Default CREATE_CHILD_SA
  const [showHexDump, setShowHexDump] = useState<boolean>(true);

  return (
    <AppShell>
      <div className="space-y-6 max-w-7xl mx-auto">
        {/* Navigation Breadcrumb */}
        <div className="flex items-center justify-between pb-2 border-b border-sentinel-border">
          <Link
            href="/sessions"
            className="flex items-center gap-1.5 text-xs font-mono-tech text-sentinel-muted hover:text-sentinel-copper transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>BACK TO SESSION EXPLORER</span>
          </Link>

          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                const blob = new Blob([JSON.stringify(session, null, 2)], {
                  type: 'application/json',
                });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `session_${session.id}.json`;
                a.click();
              }}
              className="flex items-center gap-1.5 px-3 py-1 rounded bg-sentinel-secondary border border-sentinel-border hover:border-sentinel-copper text-xs font-mono-tech text-sentinel-muted hover:text-sentinel-text transition-colors"
            >
              <Download className="w-3 h-3" />
              Canonical JSON
            </button>
            <Link
              href="/reports"
              className="flex items-center gap-1.5 px-3 py-1 rounded bg-sentinel-copper text-sentinel-bg font-mono-tech text-xs font-semibold hover:bg-sentinel-copperHover transition-colors"
            >
              <FileText className="w-3 h-3" />
              Generate Report
            </Link>
          </div>
        </div>

        {/* Header Bar */}
        <div className="panel-technical p-5 rounded-lg border-l-4 border-l-sentinel-copper">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono-tech tracking-wider uppercase text-sentinel-muted">
                  SESSION ANALYSIS
                </span>
                <span className="text-sentinel-border">•</span>
                <span className="text-[10px] font-mono-tech text-sentinel-mint">
                  ESTABLISHED AT {session.establishedAt}
                </span>
              </div>
              <div className="flex items-center gap-3">
                <h1 className="font-mono-tech text-2xl font-bold tracking-tight text-sentinel-text">
                  {session.id}
                </h1>
                <StatusBadge status={session.risk} />
                <span className="text-xs font-mono-tech px-2 py-0.5 rounded bg-sentinel-mint/10 text-sentinel-mint border border-sentinel-mint/30">
                  SECURE / MEDIUM RISK
                </span>
              </div>
            </div>

            {/* Quick Summary Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono-tech text-xs bg-sentinel-secondary/40 p-3 rounded border border-sentinel-border">
              <div>
                <span className="text-[10px] text-sentinel-muted block">SOURCE ENDPOINT</span>
                <span className="text-sentinel-text font-bold">{session.source}</span>
              </div>
              <div>
                <span className="text-[10px] text-sentinel-muted block">DESTINATION GATEWAY</span>
                <span className="text-sentinel-text font-bold">{session.destination}</span>
              </div>
              <div>
                <span className="text-[10px] text-sentinel-muted block">IKE PROTOCOL</span>
                <span className="text-sentinel-copper font-bold">{session.ikeVersion} ({session.mode})</span>
              </div>
              <div>
                <span className="text-[10px] text-sentinel-muted block">SA LIFETIME</span>
                <span className="text-sentinel-text font-bold">{session.saLifetime}s (1 hour)</span>
              </div>
            </div>
          </div>
        </div>

        {/* Section 1: IKE NEGOTIATION TIMELINE */}
        <div className="panel-technical p-5 rounded-lg space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
            <div className="flex items-center gap-2">
              <Clock className="w-4 h-4 text-sentinel-copper" />
              <h2 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                IKE Negotiation Timeline & Exchange Grammar
              </h2>
            </div>
            <span className="text-[10px] font-mono-tech text-sentinel-muted">
              Deterministic Grammatical Dissection (RFC 7296)
            </span>
          </div>

          {/* Stepper Timeline */}
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
            {session.ikeTimeline.map((step, idx) => {
              const isSelected = activeTimelineStep === idx;
              const hasWarning = step.step === 'CREATE_CHILD_SA';

              return (
                <div
                  key={step.step}
                  onClick={() => setActiveTimelineStep(idx)}
                  className={`p-3 rounded border cursor-pointer transition-all ${
                    isSelected
                      ? 'border-sentinel-copper bg-sentinel-copper/10'
                      : 'border-sentinel-border bg-sentinel-secondary/30 hover:border-sentinel-copper/50'
                  }`}
                >
                  <div className="flex items-center justify-between text-[10px] font-mono-tech mb-1">
                    <span className="text-sentinel-muted">STEP 0{idx + 1}</span>
                    <span className="text-sentinel-muted">{step.timestamp.split(' ')[0]}</span>
                  </div>
                  <div className="font-mono-tech text-xs font-bold text-sentinel-text mb-1">
                    {step.step}
                  </div>
                  <div className="flex items-center justify-between text-[11px] font-mono-tech">
                    <span className={hasWarning ? 'text-sentinel-warning' : 'text-sentinel-mint'}>
                      {hasWarning ? 'PFS WARNING' : 'VERIFIED OK'}
                    </span>
                    <span className="text-sentinel-muted">Msg #{step.messageId}</span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Active Step Deep-Dive */}
          {session.ikeTimeline[activeTimelineStep] && (
            <motion.div
              key={activeTimelineStep}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.2 }}
              className="p-4 bg-sentinel-elevated/60 border border-sentinel-border rounded space-y-3"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono-tech border-b border-sentinel-border/50 pb-2">
                <span className="text-sentinel-copper font-bold">
                  {session.ikeTimeline[activeTimelineStep].step} Dissection Details
                </span>
                <span className="text-sentinel-muted">
                  Exchange: {session.ikeTimeline[activeTimelineStep].source} → {session.ikeTimeline[activeTimelineStep].destination}
                </span>
              </div>

              <p className="text-xs text-sentinel-text leading-relaxed font-mono-tech">
                {session.ikeTimeline[activeTimelineStep].details}
              </p>

              {/* Payloads List */}
              <div className="space-y-1">
                <span className="text-[10px] font-mono-tech text-sentinel-muted uppercase">
                  Negotiated Payloads:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {session.ikeTimeline[activeTimelineStep].payloads.map((payload, i) => (
                    <span
                      key={i}
                      className="px-2 py-0.5 rounded bg-sentinel-deep border border-sentinel-border text-[11px] font-mono-tech text-sentinel-text"
                    >
                      {payload}
                    </span>
                  ))}
                </div>
              </div>

              {/* Hex Dump */}
              {session.ikeTimeline[activeTimelineStep].evidenceHex && (
                <div className="pt-2">
                  <div className="flex items-center justify-between pb-1 text-[10px] font-mono-tech text-sentinel-muted">
                    <span>RAW ISAKMP/IKEv2 WIRE BYTE SEQUENCE:</span>
                    <button
                      onClick={() => setShowHexDump(!showHexDump)}
                      className="text-sentinel-copper hover:underline"
                    >
                      {showHexDump ? 'Hide Hex' : 'Show Hex'}
                    </button>
                  </div>
                  {showHexDump && (
                    <div className="p-2.5 rounded bg-sentinel-secondary/60 border border-sentinel-border/50 font-mono-tech text-[11px] text-sentinel-muted overflow-x-auto">
                      {session.ikeTimeline[activeTimelineStep].evidenceHex}
                    </div>
                  )}
                </div>
              )}
            </motion.div>
          )}
        </div>

        {/* Section 2: CRYPTOGRAPHIC PARAMETERS & SECURITY ASSOCIATION */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Cryptographic Parameters */}
          <div className="panel-technical p-5 rounded-lg space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
              <div className="flex items-center gap-2">
                <Key className="w-4 h-4 text-sentinel-copper" />
                <h3 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                  Cryptographic Parameters
                </h3>
              </div>
              <span className="text-[10px] font-mono-tech text-sentinel-mint">
                AEAD COMBINED MODE
              </span>
            </div>

            <div className="space-y-3 font-mono-tech text-xs divide-y divide-sentinel-border/50">
              <div className="flex items-center justify-between pt-1">
                <span className="text-sentinel-muted">Encryption Cipher:</span>
                <span className="text-sentinel-text font-bold">{session.crypto.encryption}</span>
              </div>
              <div className="flex items-center justify-between pt-2">
                <span className="text-sentinel-muted">Integrity Verification:</span>
                <span className="text-sentinel-text">{session.crypto.integrity}</span>
              </div>
              <div className="flex items-center justify-between pt-2">
                <span className="text-sentinel-muted">Pseudorandom Function (PRF):</span>
                <span className="text-sentinel-copper font-medium">{session.crypto.prf}</span>
              </div>
              <div className="flex items-center justify-between pt-2">
                <span className="text-sentinel-muted">Diffie-Hellman Group:</span>
                <span className="text-sentinel-text font-bold">{session.crypto.dhGroup}</span>
              </div>
              <div className="flex items-center justify-between pt-2">
                <span className="text-sentinel-muted">Perfect Forward Secrecy:</span>
                <span className="text-sentinel-warning font-bold">
                  {session.crypto.pfsEnabled ? 'ENABLED (DEGRADED ON REKEY)' : 'DISABLED'}
                </span>
              </div>
              <div className="flex items-center justify-between pt-2">
                <span className="text-sentinel-muted">Quantum Resistance:</span>
                <span className="text-sentinel-muted">0-bit Classical (Vulnerable to Shor)</span>
              </div>
            </div>
          </div>

          {/* Security Association (SA) Telemetry */}
          <div className="panel-technical p-5 rounded-lg space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-sentinel-copper" />
                <h3 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                  Security Association (SA) State
                </h3>
              </div>
              <span className="text-[10px] font-mono-tech text-sentinel-mint">
                XFRM SYNCHRONIZED
              </span>
            </div>

            <div className="space-y-3 font-mono-tech text-xs divide-y divide-sentinel-border/50">
              <div className="flex items-center justify-between pt-1">
                <span className="text-sentinel-muted">Inbound SPI:</span>
                <span className="text-sentinel-copper font-bold">{session.spiIn}</span>
              </div>
              <div className="flex items-center justify-between pt-2">
                <span className="text-sentinel-muted">Outbound SPI:</span>
                <span className="text-sentinel-copper font-bold">{session.spiOut}</span>
              </div>
              <div className="flex items-center justify-between pt-2">
                <span className="text-sentinel-muted">Configured SA Lifetime:</span>
                <span className="text-sentinel-text">{session.saLifetime}s (3600 sec)</span>
              </div>
              <div className="flex items-center justify-between pt-2">
                <span className="text-sentinel-muted">Anti-Replay Window:</span>
                <span className="text-sentinel-mint font-bold">
                  ESN 64-bit Active (Window 64)
                </span>
              </div>
              <div className="flex items-center justify-between pt-2">
                <span className="text-sentinel-muted">Encapsulated Packets:</span>
                <span className="text-sentinel-text">{session.packetsCount.toLocaleString()} ESP Frames</span>
              </div>
              <div className="flex items-center justify-between pt-2">
                <span className="text-sentinel-muted">Transferred Volume:</span>
                <span className="text-sentinel-text">
                  {(session.bytesTransferred / (1024 * 1024)).toFixed(2)} MB
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Section 3: TRAFFIC INTELLIGENCE & METADATA EXPOSURE */}
        <div className="panel-technical p-5 rounded-lg space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-sentinel-copper" />
              <h3 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                ML Traffic Intelligence & Side-Channel Exposure
              </h3>
            </div>
            <span className="text-[10px] font-mono-tech text-sentinel-copper">
              Model: Random Forest + 1D-CNN Temporal
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
            <div className="p-3 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech">
              <div className="text-[10px] text-sentinel-muted uppercase">Predicted Traffic</div>
              <div className="text-sm font-bold text-sentinel-text mt-1">
                {session.trafficType}
              </div>
            </div>
            <div className="p-3 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech">
              <div className="text-[10px] text-sentinel-muted uppercase">AI Classification Confidence</div>
              <div className="text-xl font-bold text-sentinel-mint mt-1">
                91.4%
              </div>
            </div>
            <div className="p-3 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech">
              <div className="text-[10px] text-sentinel-muted uppercase">Anomaly Score</div>
              <div className="text-xl font-bold text-sentinel-text mt-1">
                0.18 <span className="text-xs text-sentinel-muted font-normal">/ 0.72 (NORMAL)</span>
              </div>
            </div>
            <div className="p-3 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech">
              <div className="text-[10px] text-sentinel-muted uppercase">Metadata Side-Channel</div>
              <div className="text-sm font-bold text-sentinel-warning mt-1">
                MEDIUM RISK (33ms Burst)
              </div>
            </div>
          </div>
        </div>

        {/* Section 4: EVIDENCE-BACKED RAG SECURITY ANALYSIS */}
        {session.ragAnalysis && (
          <div className="panel-technical p-5 rounded-lg space-y-4 border border-sentinel-border bg-sentinel-elevated/40">
            <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-sentinel-mint" />
                <h3 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                  Grounded Security Assessment & Technical Remediation
                </h3>
              </div>
              <span className="text-[10px] font-mono-tech px-2 py-0.5 rounded bg-sentinel-mint/10 text-sentinel-mint border border-sentinel-mint/30">
                EVIDENCE VERIFIED
              </span>
            </div>

            <div className="space-y-4 text-xs font-sans leading-relaxed">
              <div>
                <h4 className="text-[11px] font-mono-tech text-sentinel-copper uppercase font-semibold mb-1">
                  Autonomous Findings Synthesis:
                </h4>
                <p className="text-sentinel-text bg-sentinel-secondary/30 p-3 rounded border border-sentinel-border font-mono-tech text-xs leading-relaxed">
                  {session.ragAnalysis.summary}
                </p>
              </div>

              <div>
                <h4 className="text-[11px] font-mono-tech text-sentinel-copper uppercase font-semibold mb-1">
                  Deterministic Evidence Citations:
                </h4>
                <ul className="space-y-1.5 font-mono-tech text-xs">
                  {session.ragAnalysis.groundedEvidence.map((ev, i) => (
                    <li key={i} className="flex items-start gap-2 text-sentinel-muted">
                      <span className="text-sentinel-mint font-bold mt-0.5">•</span>
                      <span>{ev}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="p-3.5 rounded bg-sentinel-elevated border border-sentinel-border space-y-1.5">
                <h4 className="text-[11px] font-mono-tech text-sentinel-mint uppercase font-semibold">
                  Required Gateway Configuration Patch:
                </h4>
                <p className="font-mono-tech text-xs text-sentinel-text">
                  {session.ragAnalysis.technicalRemediation}
                </p>
                <div className="pt-2 flex items-center gap-2 font-mono-tech text-[10px] text-sentinel-muted">
                  <span>Cited Standards:</span>
                  {session.ragAnalysis.rfcCitations.map((cite, idx) => (
                    <span key={idx} className="px-1.5 py-0.5 bg-sentinel-secondary rounded border border-sentinel-border">
                      {cite}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}
