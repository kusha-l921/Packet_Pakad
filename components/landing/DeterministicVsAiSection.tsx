'use client';

import React from 'react';
import { ShieldCheck, Cpu, FileSpreadsheet, ArrowDown, ArrowRight, CheckCircle2 } from 'lucide-react';

export default function DeterministicVsAiSection() {
  return (
    <section id="architecture" className="py-20 border-b border-sentinel-border/70 bg-sentinel-panel/30">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="mb-14">
          <div className="text-xs font-mono uppercase tracking-wider text-sentinel-copper mb-2 flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-sentinel-copper" />
            <span>Architectural Integrity & Separation of Concerns</span>
          </div>
          <h2 className="text-2xl sm:text-3xl lg:text-4xl font-bold tracking-tight text-sentinel-text">
            DETERMINISTIC PRECISION VS. AI INTELLIGENCE
          </h2>
          <p className="mt-3 text-sm text-sentinel-text-muted max-w-2xl font-mono">
            Security scores and compliance decisions are 100% mathematically deterministic. AI is strictly confined to 
            side-channel inference, and RAG is utilized solely for evidence-grounded report synthesis.
          </p>
        </div>

        {/* 3 Columns: Deterministic, AI/ML, and RAG Reporting */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
          {/* Column 1: Deterministic Engine */}
          <div className="rounded-xl border border-sentinel-border bg-sentinel-panel p-6 flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-3 pb-3 mb-4 border-b border-sentinel-border">
                <div className="w-8 h-8 rounded border border-sentinel-mint/50 bg-sentinel-bg flex items-center justify-center text-sentinel-mint">
                  <ShieldCheck className="w-4 h-4 stroke-[1.8]" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-sentinel-text tracking-wide">
                    DETERMINISTIC ANALYSIS
                  </h3>
                  <span className="text-[10px] font-mono text-sentinel-mint uppercase tracking-wider">
                    Ground Truth Rule Engine
                  </span>
                </div>
              </div>

              <p className="text-xs text-sentinel-text-muted leading-relaxed mb-4">
                Executes formal protocol grammars and cryptographic equations without hallucination risk.
              </p>

              <ul className="space-y-2 font-mono text-xs text-sentinel-text">
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-mint shrink-0" />
                  <span>Protocol Grammar Parsing</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-mint shrink-0" />
                  <span>IKE & ESP Extraction</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-mint shrink-0" />
                  <span>Session Correlation & SPI Map</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-mint shrink-0" />
                  <span>RFC 7296 / 4301 Compliance</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-mint shrink-0" />
                  <span>Child SA Lifetime & PFS Audit</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-mint shrink-0" />
                  <span>64-bit Anti-Replay Protection</span>
                </li>
              </ul>
            </div>

            <div className="mt-6 pt-3 border-t border-sentinel-border text-[10px] font-mono text-sentinel-mint font-semibold">
              Calculates Formal Security Score (82/100)
            </div>
          </div>

          {/* Column 2: AI / ML Analysis */}
          <div className="rounded-xl border border-sentinel-border bg-sentinel-panel p-6 flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-3 pb-3 mb-4 border-b border-sentinel-border">
                <div className="w-8 h-8 rounded border border-sentinel-copper/50 bg-sentinel-bg flex items-center justify-center text-sentinel-copper">
                  <Cpu className="w-4 h-4 stroke-[1.8]" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-sentinel-text tracking-wide">
                    AI / ML INFERENCE
                  </h3>
                  <span className="text-[10px] font-mono text-sentinel-copper uppercase tracking-wider">
                    Envelope Behavioral Models
                  </span>
                </div>
              </div>

              <p className="text-xs text-sentinel-text-muted leading-relaxed mb-4">
                Inspects wire timing intervals and packet size distributions without decrypting payloads.
              </p>

              <ul className="space-y-2 font-mono text-xs text-sentinel-text">
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-copper shrink-0" />
                  <span>Encrypted Traffic Classification</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-copper shrink-0" />
                  <span>Burst Entropy Profiling</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-copper shrink-0" />
                  <span>Frame Cadence Detection (30Hz)</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-copper shrink-0" />
                  <span>TFC Padding Absence Alerts</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-copper shrink-0" />
                  <span>Covert Tunnel Anomaly Discovery</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-copper shrink-0" />
                  <span>Probabilistic Confidence Metric</span>
                </li>
              </ul>
            </div>

            <div className="mt-6 pt-3 border-t border-sentinel-border text-[10px] font-mono text-sentinel-copper font-semibold">
              Surfaces Side-Channel Metadata Risk
            </div>
          </div>

          {/* Column 3: Report Intelligence */}
          <div className="rounded-xl border border-sentinel-border bg-sentinel-panel p-6 flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-3 pb-3 mb-4 border-b border-sentinel-border">
                <div className="w-8 h-8 rounded border border-sentinel-info/50 bg-sentinel-bg flex items-center justify-center text-sentinel-info">
                  <FileSpreadsheet className="w-4 h-4 stroke-[1.8]" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-sentinel-text tracking-wide">
                    REPORT INTELLIGENCE
                  </h3>
                  <span className="text-[10px] font-mono text-sentinel-info uppercase tracking-wider">
                    Evidence-Grounded RAG
                  </span>
                </div>
              </div>

              <p className="text-xs text-sentinel-text-muted leading-relaxed mb-4">
                RAG synthesizes verified findings into executive debriefs. It never decides security scores.
              </p>

              <ul className="space-y-2 font-mono text-xs text-sentinel-text">
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-info shrink-0" />
                  <span>Strict Evidence Locking</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-info shrink-0" />
                  <span>Zero-Hallucination Guardrails</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-info shrink-0" />
                  <span>RFC Specification Anchoring</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-info shrink-0" />
                  <span>Executable swanctl Diff Patching</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-info shrink-0" />
                  <span>Executive & Technical Debriefs</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-info shrink-0" />
                  <span>Compliance Audit Trail Ledger</span>
                </li>
              </ul>
            </div>

            <div className="mt-6 pt-3 border-t border-sentinel-border text-[10px] font-mono text-sentinel-info font-semibold">
              Translates Ground Truth to Actionable Reports
            </div>
          </div>
        </div>

        {/* Linear Decision Flow Diagram */}
        <div className="p-6 rounded-xl border border-sentinel-border bg-[#0B0C0D] font-mono text-xs">
          <div className="text-[11px] text-sentinel-copper uppercase font-semibold mb-4 text-center">
            FACTUAL EVIDENCE PIPELINE PIPELINE HIERARCHY
          </div>

          <div className="flex flex-col md:flex-row items-center justify-between gap-3 text-center">
            <div className="p-3 rounded border border-sentinel-border bg-[#151719] w-full md:w-auto flex-1">
              <span className="text-[10px] text-sentinel-text-muted">STAGE 1</span>
              <div className="font-bold text-sentinel-text">ANALYTICAL ENGINES</div>
            </div>
            <ArrowRight className="w-4 h-4 text-sentinel-copper rotate-90 md:rotate-0" />
            <div className="p-3 rounded border border-sentinel-border bg-[#151719] w-full md:w-auto flex-1">
              <span className="text-[10px] text-sentinel-text-muted">STAGE 2</span>
              <div className="font-bold text-sentinel-text">SECURITY FINDINGS</div>
            </div>
            <ArrowRight className="w-4 h-4 text-sentinel-copper rotate-90 md:rotate-0" />
            <div className="p-3 rounded border border-sentinel-border bg-[#151719] w-full md:w-auto flex-1">
              <span className="text-[10px] text-sentinel-text-muted">STAGE 3</span>
              <div className="font-bold text-sentinel-text">VERIFIED EVIDENCE</div>
            </div>
            <ArrowRight className="w-4 h-4 text-sentinel-copper rotate-90 md:rotate-0" />
            <div className="p-3 rounded border border-sentinel-info/60 bg-sentinel-info/10 w-full md:w-auto flex-1">
              <span className="text-[10px] text-sentinel-info">STAGE 4</span>
              <div className="font-bold text-sentinel-info">RAG SYNTHESIS</div>
            </div>
            <ArrowRight className="w-4 h-4 text-sentinel-copper rotate-90 md:rotate-0" />
            <div className="p-3 rounded border border-sentinel-mint/60 bg-sentinel-mint/10 w-full md:w-auto flex-1">
              <span className="text-[10px] text-sentinel-mint">STAGE 5</span>
              <div className="font-bold text-sentinel-mint">EXECUTIVE REPORT</div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
