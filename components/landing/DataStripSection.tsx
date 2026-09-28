'use client';

import React, { useEffect, useState } from 'react';
import { ArrowRight, CheckCircle2, Shield, Activity, Terminal } from 'lucide-react';

const PIPELINE_NODES = [
  { step: 'IKE', label: 'IKEv2 Grammars', sub: 'UDP 500 / 4500' },
  { step: 'ESP', label: 'ESP Envelopes', sub: 'Proto 50 (RFC 4303)' },
  { step: 'SESSION', label: 'SA Correlation', sub: 'SPI & Nonce Map' },
  { step: 'CRYPTO', label: 'Posture Audit', sub: 'Suite-B / CNSA' },
  { step: 'TRAFFIC', label: 'ML Inference', sub: 'Entropy & Cadence' },
  { step: 'RISK', label: 'Vector Synthesis', sub: 'Score: 82 / 100' },
];

const LOG_EVENTS = [
  '[04:18:21.102] PARSER: Matched IKE_SA_INIT exchange. Proposal 01: ENCR_AES_GCM_256, PRF_HMAC_SHA384, DH_GROUP_19.',
  '[04:18:21.340] INGRESS: ESP Sequence #18419 decrypted header verified. Anti-replay window sliding (0 drops).',
  '[04:18:21.829] RFC_ENGINE: Rule RFC-C-027 triggered on CREATE_CHILD_SA: Key exchange payload KEs absent.',
  '[04:18:22.001] ML_CLASSIFY: High-entropy burst payload pattern matches encoded H.264 VBR streaming profile (1.2 Mbps).',
  '[04:18:22.415] RISK_SYNTHESIS: Deterministic score calculated: 82/100 (Medium). RAG report evidence locked.',
];

export default function DataStripSection() {
  const [activeStep, setActiveStep] = useState(0);
  const [logIndex, setLogIndex] = useState(0);

  useEffect(() => {
    const stepInterval = setInterval(() => {
      setActiveStep((prev) => (prev + 1) % PIPELINE_NODES.length);
    }, 2000);

    const logInterval = setInterval(() => {
      setLogIndex((prev) => (prev + 1) % LOG_EVENTS.length);
    }, 2800);

    return () => {
      clearInterval(stepInterval);
      clearInterval(logInterval);
    };
  }, []);

  return (
    <section className="py-16 border-b border-sentinel-border/70 bg-[#0B0C0D] overflow-hidden">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-10">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-sentinel-border bg-sentinel-panel/60 mb-3">
            <span className="w-1.5 h-1.5 rounded-full bg-sentinel-copper animate-ping" />
            <span className="text-[11px] font-mono tracking-wider text-sentinel-text-muted uppercase">
              Live Analytical Stream
            </span>
          </div>
          <h2 className="text-xl sm:text-2xl lg:text-3xl font-bold tracking-tight text-sentinel-text">
            FROM ENCRYPTED PACKETS TO EXPLAINABLE FINDINGS
          </h2>
          <p className="mt-2 text-xs sm:text-sm text-sentinel-text-muted max-w-xl mx-auto font-mono">
            Continuous packet state extraction transforming high-speed ESP frames into verified cryptographic intelligence.
          </p>
        </div>

        {/* Visual Horizontal Pipeline with Animated Packet Traces */}
        <div className="relative p-6 rounded-xl border border-sentinel-border bg-[#101214] mb-8 shadow-xl">
          {/* Subtle background circuit line */}
          <div className="absolute top-1/2 left-8 right-8 h-[2px] bg-sentinel-border -translate-y-1/2 hidden md:block" />

          <div className="grid grid-cols-2 md:grid-cols-6 gap-4 relative z-10">
            {PIPELINE_NODES.map((node, i) => {
              const isCurrent = activeStep === i;
              const isPassed = activeStep > i;

              return (
                <div
                  key={i}
                  className={`p-3.5 rounded-lg border text-center transition-all duration-300 ${
                    isCurrent
                      ? 'border-sentinel-copper bg-sentinel-panel shadow-lg shadow-sentinel-copper/20 scale-105'
                      : isPassed
                      ? 'border-sentinel-mint/50 bg-sentinel-panel/80'
                      : 'border-sentinel-border bg-sentinel-bg/90'
                  }`}
                >
                  <div className="flex items-center justify-center gap-1.5 mb-1.5">
                    <span
                      className={`w-2 h-2 rounded-full ${
                        isCurrent
                          ? 'bg-sentinel-copper animate-pulse'
                          : isPassed
                          ? 'bg-sentinel-mint'
                          : 'bg-sentinel-border'
                      }`}
                    />
                    <span
                      className={`text-xs font-mono font-bold tracking-wider ${
                        isCurrent
                          ? 'text-sentinel-copper'
                          : isPassed
                          ? 'text-sentinel-mint'
                          : 'text-sentinel-text-muted'
                      }`}
                    >
                      {node.step}
                    </span>
                  </div>
                  <div className="text-xs font-medium text-sentinel-text mb-0.5 truncate">
                    {node.label}
                  </div>
                  <div className="text-[10px] font-mono text-sentinel-text-muted truncate">
                    {node.sub}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Terminal Telemetry Log Box */}
        <div className="p-4 rounded-lg border border-sentinel-border bg-[#0B0C0D] font-mono text-xs">
          <div className="flex items-center justify-between border-b border-sentinel-border/70 pb-2 mb-2 text-sentinel-text-muted text-[11px]">
            <div className="flex items-center gap-2">
              <Terminal className="w-3.5 h-3.5 text-sentinel-copper" />
              <span>REAL-TIME DISSECTION LOG FEED</span>
            </div>
            <span className="text-sentinel-mint">● FASTAPI ADAPTER 12ms</span>
          </div>

          <div className="space-y-1.5">
            {LOG_EVENTS.map((event, idx) => (
              <div
                key={idx}
                className={`transition-opacity duration-300 text-[11px] truncate ${
                  idx === logIndex
                    ? 'text-sentinel-text font-bold bg-sentinel-panel/60 px-2 py-0.5 rounded border-l-2 border-sentinel-copper'
                    : 'text-sentinel-text-muted/70 px-2 py-0.5'
                }`}
              >
                {event}
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
