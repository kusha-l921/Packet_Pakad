'use client';

import React from 'react';
import { 
  Check, 
  AlertTriangle, 
  ShieldAlert, 
  ArrowRight, 
  Binary, 
  Gauge, 
  Cpu, 
  Terminal,
  FileText
} from 'lucide-react';

interface AssessmentPreviewProps {
  onOpenConsole: () => void;
}

export default function AssessmentPreview({ onOpenConsole }: AssessmentPreviewProps) {
  const findings = [
    { text: 'AES-256-GCM AEAD Cipher Detected', type: 'ok', tag: 'RFC 8221' },
    { text: 'IKEv2 Negotiation Fully Compliant', type: 'ok', tag: 'RFC 7296' },
    { text: 'PFS Enabled for Initial IKE SA Exchange', type: 'ok', tag: 'DH GROUP 19' },
    { text: 'SA Lifetime Exceeds Sovereign Hardening Baseline', type: 'warn', tag: 'SEC-D09' },
    { text: 'Metadata Exposure Detected via 30Hz Frame Cadence', type: 'warn', tag: 'META-D14' },
    { text: 'Anti-Replay Protection Enabled (64-bit ESN Window)', type: 'ok', tag: 'RFC 4303' },
  ];

  return (
    <section id="assessment" className="py-20 border-b border-sentinel-border/70 bg-sentinel-bg">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="flex flex-col md:flex-row md:items-end justify-between mb-12">
          <div>
            <div className="text-xs font-mono uppercase tracking-wider text-sentinel-copper mb-2 flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-sentinel-copper" />
              <span>Evidence-Grounded Output Preview</span>
            </div>
            <h2 className="text-2xl sm:text-3xl lg:text-4xl font-bold tracking-tight text-sentinel-text">
              REAL-TIME CRYPTOGRAPHIC ASSESSMENT
            </h2>
          </div>
          <p className="mt-3 md:mt-0 text-xs sm:text-sm text-sentinel-text-muted max-w-md font-mono">
            Direct output generated across active session <span className="text-sentinel-copper font-bold">IPSEC-00421</span> before executive report generation.
          </p>
        </div>

        {/* Realistic Dashboard Assessment Output Preview Card */}
        <div className="rounded-xl border border-sentinel-border bg-sentinel-panel p-6 sm:p-8 shadow-xl">
          {/* Top KPI Stats Strip */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pb-6 mb-6 border-b border-sentinel-border">
            {/* Metric 1: Security Assessment */}
            <div className="p-4 rounded-lg border border-sentinel-border/80 bg-sentinel-bg">
              <div className="text-[10px] font-mono uppercase tracking-wider text-sentinel-text-muted mb-1">
                SECURITY SCORE
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl sm:text-4xl font-bold font-mono text-sentinel-text">
                  82
                </span>
                <span className="text-xs font-mono text-sentinel-text-muted">/ 100</span>
              </div>
              <div className="mt-2 text-[10px] font-mono text-sentinel-copper">
                NTRO Benchmark C3
              </div>
            </div>

            {/* Metric 2: Risk Level */}
            <div className="p-4 rounded-lg border border-sentinel-border/80 bg-sentinel-bg">
              <div className="text-[10px] font-mono uppercase tracking-wider text-sentinel-text-muted mb-1">
                RISK LEVEL
              </div>
              <div className="flex items-center gap-2 mt-1">
                <span className="px-2 py-0.5 rounded text-xs font-mono font-bold uppercase bg-sentinel-warning/15 text-sentinel-warning border border-sentinel-warning/30">
                  MEDIUM
                </span>
              </div>
              <div className="mt-3 text-[10px] font-mono text-sentinel-text-muted">
                2 Non-Compliant Rules
              </div>
            </div>

            {/* Metric 3: Compliance */}
            <div className="p-4 rounded-lg border border-sentinel-border/80 bg-sentinel-bg">
              <div className="text-[10px] font-mono uppercase tracking-wider text-sentinel-text-muted mb-1">
                RFC COMPLIANCE
              </div>
              <div className="text-3xl sm:text-4xl font-bold font-mono text-sentinel-mint">
                87%
              </div>
              <div className="mt-2 text-[10px] font-mono text-sentinel-text-muted">
                18 Pass • 4 Warn • 2 Fail
              </div>
            </div>

            {/* Metric 4: AI Confidence */}
            <div className="p-4 rounded-lg border border-sentinel-border/80 bg-sentinel-bg">
              <div className="text-[10px] font-mono uppercase tracking-wider text-sentinel-text-muted mb-1">
                ML CONFIDENCE
              </div>
              <div className="text-3xl sm:text-4xl font-bold font-mono text-sentinel-text">
                94.2%
              </div>
              <div className="mt-2 text-[10px] font-mono text-sentinel-copper">
                H.264/RTP Inferred
              </div>
            </div>
          </div>

          {/* Technical Findings List */}
          <div className="space-y-3 mb-6">
            <div className="text-xs font-mono uppercase tracking-wider text-sentinel-text-muted mb-2">
              DISSECTED SESSION FINDINGS (IPSEC-00421)
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
              {findings.map((item, i) => (
                <div
                  key={i}
                  className={`p-3 rounded-lg border flex items-center justify-between ${
                    item.type === 'ok'
                      ? 'border-sentinel-border bg-sentinel-bg/80 text-sentinel-text'
                      : 'border-sentinel-warning/40 bg-sentinel-warning/5 text-sentinel-text'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    {item.type === 'ok' ? (
                      <Check className="w-4 h-4 text-sentinel-mint shrink-0" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 text-sentinel-warning shrink-0" />
                    )}
                    <span className="text-[11px] sm:text-xs">{item.text}</span>
                  </div>
                  <span
                    className={`text-[9px] px-1.5 py-0.5 rounded uppercase font-semibold shrink-0 ml-2 ${
                      item.type === 'ok'
                        ? 'border border-sentinel-border bg-sentinel-panel text-sentinel-text-muted'
                        : 'border border-sentinel-warning/40 bg-sentinel-warning/10 text-sentinel-warning'
                    }`}
                  >
                    {item.tag}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Action CTA Bar */}
          <div className="pt-4 border-t border-sentinel-border flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="text-[11px] font-mono text-sentinel-text-muted">
              Explore the full interactive session analysis in the live Security Console.
            </div>

            <button
              onClick={onOpenConsole}
              className="px-4 py-2 rounded text-xs font-mono uppercase tracking-wider font-semibold border border-sentinel-copper bg-sentinel-copper text-white dark:text-[#0B0C0D] hover:bg-sentinel-copper/90 transition-colors flex items-center gap-2 group"
            >
              <span>Inspect Full Session In Console</span>
              <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}
