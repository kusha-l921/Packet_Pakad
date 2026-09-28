'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { 
  Radio, 
  Download, 
  FileText, 
  ExternalLink, 
  Check, 
  AlertTriangle, 
  Key, 
  ShieldCheck, 
  RefreshCw, 
  Layers, 
  Terminal,
  Activity,
  ArrowRight,
  Copy,
  Clock,
  CheckCircle2
} from 'lucide-react';
import { 
  INITIAL_PIPELINE_STAGES, 
  MOCK_FINDINGS, 
  MOCK_SESSIONS, 
  PipelineStage,
  SecurityFinding,
  MonitoredSession
} from '@/lib/mock/securityData';

export default function SecurityOverviewDashboard() {
  const [pipelineStages] = useState<PipelineStage[]>(INITIAL_PIPELINE_STAGES);
  const [findings] = useState<SecurityFinding[]>(MOCK_FINDINGS);
  const [sessions] = useState<MonitoredSession[]>(MOCK_SESSIONS);
  const [selectedTunnelTab, setSelectedTunnelTab] = useState<'ESP1' | 'IKE' | 'ESP2'>('ESP1');
  const [copiedDiff, setCopiedDiff] = useState(false);

  const handleCopyDiff = () => {
    setCopiedDiff(true);
    setTimeout(() => setCopiedDiff(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* ==================================================== */}
      {/* 1. DASHBOARD HEADER & CONTEXT                       */}
      {/* ==================================================== */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-sentinel-border">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2.5 h-2.5 rounded-full bg-sentinel-copper animate-pulse" />
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-sentinel-text uppercase font-mono">
              SECURITY OVERVIEW DASHBOARD
            </h1>
          </div>
          <div className="text-xs font-mono text-sentinel-text-muted flex items-center gap-2">
            <span>NTRO Benchmark Problem Statement 26160</span>
            <span>•</span>
            <span>Sovereign Defense Cryptographic Assessment</span>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2.5 font-mono text-xs">
          <button className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-sentinel-border bg-[#151719] hover:border-sentinel-copper/50 text-sentinel-text transition-colors">
            <Radio className="w-3.5 h-3.5 text-sentinel-copper" />
            <span>Live Stream</span>
          </button>

          <button className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-sentinel-border bg-[#151719] hover:border-sentinel-copper/50 text-sentinel-text transition-colors">
            <Download className="w-3.5 h-3.5 text-sentinel-text-muted" />
            <span>Export Session JSON</span>
          </button>

          <button className="flex items-center gap-1.5 px-3.5 py-1.5 rounded border border-sentinel-copper bg-sentinel-copper text-white dark:text-[#0B0C0D] font-bold hover:bg-sentinel-copper/90 transition-colors">
            <FileText className="w-3.5 h-3.5" />
            <span>Exec Report</span>
          </button>
        </div>
      </div>

      {/* ==================================================== */}
      {/* 2. TOP 5 KPI SUMMARY METRIC CARDS                    */}
      {/* ==================================================== */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3.5 font-mono">
        {/* Metric 1 */}
        <div className="p-4 rounded-lg border border-sentinel-border bg-[#101214] flex flex-col justify-between">
          <div className="text-[10px] uppercase text-sentinel-text-muted tracking-wider mb-1">
            SECURITY SCORE
          </div>
          <div className="flex items-baseline gap-1.5 my-1">
            <span className="text-3xl font-bold text-sentinel-text">82</span>
            <span className="text-xs text-sentinel-text-muted">/ 100</span>
          </div>
          <div className="text-[10px] text-sentinel-copper">
            NTRO Benchmark C3
          </div>
        </div>

        {/* Metric 2 */}
        <div className="p-4 rounded-lg border border-sentinel-border bg-[#101214] flex flex-col justify-between">
          <div className="text-[10px] uppercase text-sentinel-text-muted tracking-wider mb-1">
            RISK POSTURE
          </div>
          <div className="my-1">
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-bold uppercase bg-sentinel-warning/15 text-sentinel-warning border border-sentinel-warning/30">
              <span className="w-1.5 h-1.5 rounded-full bg-sentinel-warning" />
              <span>MEDIUM</span>
            </span>
          </div>
          <div className="text-[10px] text-sentinel-text-muted">
            2 Hardening Deltas
          </div>
        </div>

        {/* Metric 3 */}
        <div className="p-4 rounded-lg border border-sentinel-border bg-[#101214] flex flex-col justify-between">
          <div className="text-[10px] uppercase text-sentinel-text-muted tracking-wider mb-1">
            RFC COMPLIANCE
          </div>
          <div className="flex items-baseline gap-1.5 my-1">
            <span className="text-3xl font-bold text-sentinel-mint">87%</span>
            <span className="text-xs text-sentinel-mint/80">PASSED</span>
          </div>
          <div className="text-[10px] text-sentinel-text-muted">
            18 Pass • 4 Warn • 2 Fail
          </div>
        </div>

        {/* Metric 4 */}
        <div className="p-4 rounded-lg border border-sentinel-border bg-[#101214] flex flex-col justify-between">
          <div className="text-[10px] uppercase text-sentinel-text-muted tracking-wider mb-1">
            ML CLASSIFIER CONFIDENCE
          </div>
          <div className="flex items-baseline gap-1.5 my-1">
            <span className="text-3xl font-bold text-sentinel-text">94.2%</span>
            <span className="text-xs text-sentinel-copper">H.264/RTP</span>
          </div>
          <div className="text-[10px] text-sentinel-text-muted">
            Frame Cadence 30Hz
          </div>
        </div>

        {/* Metric 5 */}
        <div className="p-4 rounded-lg border border-sentinel-border bg-[#101214] flex flex-col justify-between col-span-2 md:col-span-1">
          <div className="text-[10px] uppercase text-sentinel-text-muted tracking-wider mb-1">
            ACTIVE SESSIONS
          </div>
          <div className="flex items-baseline gap-2 my-1">
            <span className="text-3xl font-bold text-sentinel-text">24</span>
            <span className="text-[11px] text-sentinel-mint font-semibold flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-sentinel-mint animate-pulse" />
              <span>SYNCHRONIZED</span>
            </span>
          </div>
          <div className="text-[10px] text-sentinel-text-muted">
            4 Core Gateways
          </div>
        </div>
      </div>

      {/* ==================================================== */}
      {/* 3. ROW 2: DETAILED SECURITY ASSESSMENT BREAKDOWN      */}
      {/* ==================================================== */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 font-mono text-xs">
        {/* Left: Deterministic Score Breakdown */}
        <div className="lg:col-span-6 p-5 rounded-xl border border-sentinel-border bg-[#101214] flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 mb-4 border-b border-sentinel-border/70">
              <div>
                <span className="text-[10px] uppercase tracking-wider text-sentinel-text-muted">
                  CURRENT SECURITY ASSESSMENT
                </span>
                <div className="text-xs font-bold text-sentinel-copper">
                  IPSEC-00421 • Analyzed 2 minutes ago
                </div>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-sentinel-warning/15 text-sentinel-warning border border-sentinel-warning/30">
                ● MEDIUM
              </span>
            </div>

            {/* Score Big Display */}
            <div className="flex items-baseline gap-3 mb-2">
              <span className="text-5xl font-black text-sentinel-text tracking-tight">82</span>
              <span className="text-sm text-sentinel-text-muted">/ 100</span>
              <div className="ml-auto text-right">
                <span className="text-xs font-bold text-sentinel-warning">MEDIUM RISK POSTURE</span>
                <div className="text-[10px] text-sentinel-text-muted">NTRO Benchmark C3</div>
              </div>
            </div>

            {/* Progress Bar */}
            <div className="w-full h-1.5 bg-sentinel-border/60 rounded-full mb-6 overflow-hidden">
              <div className="h-full bg-gradient-to-r from-sentinel-mint via-sentinel-copper to-sentinel-warning w-[82%]" />
            </div>

            {/* Deterministic Vector Table */}
            <div className="space-y-2">
              <div className="text-[10px] uppercase text-sentinel-text-muted font-semibold tracking-wider mb-2">
                DETERMINISTIC SCORE BREAKDOWN
              </div>
              <div className="grid grid-cols-2 gap-x-6 gap-y-2.5">
                <div>
                  <div className="flex justify-between mb-1">
                    <span className="text-sentinel-text-muted">Cryptography</span>
                    <span className="text-sentinel-text font-bold">25 / 30</span>
                  </div>
                  <div className="w-full h-1 bg-sentinel-border rounded"><div className="h-full bg-sentinel-mint w-[83%]" /></div>
                </div>
                <div>
                  <div className="flex justify-between mb-1">
                    <span className="text-sentinel-text-muted">RFC Compliance</span>
                    <span className="text-sentinel-text font-bold">18 / 20</span>
                  </div>
                  <div className="w-full h-1 bg-sentinel-border rounded"><div className="h-full bg-sentinel-mint w-[90%]" /></div>
                </div>
                <div>
                  <div className="flex justify-between mb-1">
                    <span className="text-sentinel-text-muted">SA Security</span>
                    <span className="text-sentinel-text font-bold">15 / 20</span>
                  </div>
                  <div className="w-full h-1 bg-sentinel-border rounded"><div className="h-full bg-sentinel-copper w-[75%]" /></div>
                </div>
                <div>
                  <div className="flex justify-between mb-1">
                    <span className="text-sentinel-text-muted">Anti-Replay</span>
                    <span className="text-sentinel-text font-bold">10 / 10</span>
                  </div>
                  <div className="w-full h-1 bg-sentinel-border rounded"><div className="h-full bg-sentinel-mint w-[100%]" /></div>
                </div>
                <div>
                  <div className="flex justify-between mb-1">
                    <span className="text-sentinel-text-muted">Forward Secrecy</span>
                    <span className="text-sentinel-text font-bold">08 / 10</span>
                  </div>
                  <div className="w-full h-1 bg-sentinel-border rounded"><div className="h-full bg-sentinel-copper w-[80%]" /></div>
                </div>
                <div>
                  <div className="flex justify-between mb-1">
                    <span className="text-sentinel-text-muted">Metadata Leakage</span>
                    <span className="text-sentinel-text font-bold">06 / 10</span>
                  </div>
                  <div className="w-full h-1 bg-sentinel-border rounded"><div className="h-full bg-sentinel-warning w-[60%]" /></div>
                </div>
              </div>
            </div>
          </div>

          <div className="mt-5 pt-3 border-t border-sentinel-border/70 flex items-center justify-between text-[11px] text-sentinel-text-muted">
            <span>Engine Model: SovereignNet v4.19</span>
            <span className="text-sentinel-copper hover:underline cursor-pointer flex items-center gap-1">
              <span>View Proof Ledger</span>
              <ArrowRight className="w-3 h-3" />
            </span>
          </div>
        </div>

        {/* Right: Security Posture Attributes */}
        <div className="lg:col-span-6 p-5 rounded-xl border border-sentinel-border bg-[#101214] flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 mb-4 border-b border-sentinel-border/70">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-sentinel-copper" />
                <span className="font-bold text-xs uppercase tracking-wider text-sentinel-text">
                  SECURITY POSTURE ATTRIBUTES
                </span>
              </div>
              <span className="text-[10px] px-2 py-0.5 rounded border border-sentinel-border bg-[#151719] text-sentinel-text-muted font-bold">
                SOVEREIGN STANDARD
              </span>
            </div>

            <div className="space-y-3.5">
              {/* Attribute 1 */}
              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-sentinel-text flex items-center gap-1.5">
                    <Key className="w-3 h-3 text-sentinel-copper" />
                    <span>Cryptographic Strength</span>
                  </span>
                  <span className="text-sentinel-mint font-bold">STRONG</span>
                </div>
                {/* Segmented Bar */}
                <div className="flex gap-1">
                  {[...Array(6)].map((_, i) => (
                    <div key={i} className="h-1.5 flex-1 bg-sentinel-mint rounded-sm" />
                  ))}
                </div>
              </div>

              {/* Attribute 2 */}
              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-sentinel-text flex items-center gap-1.5">
                    <CheckCircle2 className="w-3 h-3 text-sentinel-mint" />
                    <span>Configuration Compliance</span>
                  </span>
                  <span className="text-sentinel-copper font-bold">87%</span>
                </div>
                <div className="flex gap-1">
                  {[...Array(5)].map((_, i) => (
                    <div key={i} className="h-1.5 flex-1 bg-sentinel-copper rounded-sm" />
                  ))}
                  <div className="h-1.5 flex-1 bg-sentinel-border rounded-sm" />
                </div>
              </div>

              {/* Attribute 3 */}
              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-sentinel-text flex items-center gap-1.5">
                    <RefreshCw className="w-3 h-3 text-sentinel-warning" />
                    <span>Forward Secrecy (PFS)</span>
                  </span>
                  <span className="text-sentinel-warning font-bold">ENABLED (DEGRADED REKEY)</span>
                </div>
                <div className="flex gap-1">
                  {[...Array(4)].map((_, i) => (
                    <div key={i} className="h-1.5 flex-1 bg-sentinel-warning rounded-sm" />
                  ))}
                  {[...Array(2)].map((_, i) => (
                    <div key={i} className="h-1.5 flex-1 bg-sentinel-border rounded-sm" />
                  ))}
                </div>
              </div>

              {/* Attribute 4 */}
              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-sentinel-text flex items-center gap-1.5">
                    <ShieldCheck className="w-3 h-3 text-sentinel-mint" />
                    <span>Anti-Replay (ESN 64-bit)</span>
                  </span>
                  <span className="text-sentinel-mint font-bold">ENABLED</span>
                </div>
                <div className="flex gap-1">
                  {[...Array(6)].map((_, i) => (
                    <div key={i} className="h-1.5 flex-1 bg-sentinel-mint rounded-sm" />
                  ))}
                </div>
              </div>

              {/* Attribute 5 */}
              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-sentinel-text flex items-center gap-1.5">
                    <Activity className="w-3 h-3 text-sentinel-copper" />
                    <span>Metadata Exposure</span>
                  </span>
                  <span className="text-sentinel-copper font-bold">MEDIUM</span>
                </div>
                <div className="flex gap-1">
                  {[...Array(3)].map((_, i) => (
                    <div key={i} className="h-1.5 flex-1 bg-sentinel-copper rounded-sm" />
                  ))}
                  {[...Array(3)].map((_, i) => (
                    <div key={i} className="h-1.5 flex-1 bg-sentinel-border rounded-sm" />
                  ))}
                </div>
              </div>
            </div>
          </div>

          <div className="mt-5 pt-3 border-t border-sentinel-border/70 flex items-center justify-between text-[11px] text-sentinel-text-muted">
            <span>Framework: NTRO-RFC-C3</span>
            <span className="text-sentinel-warning font-semibold">Hardening Delta: -18 pts</span>
          </div>
        </div>
      </div>

      {/* ==================================================== */}
      {/* 4. ROW 3: LIVE IPSEC TUNNEL TOPOGRAPHY & ENVELOPE    */}
      {/* ==================================================== */}
      <div className="p-5 rounded-xl border border-sentinel-border bg-[#101214] font-mono text-xs">
        {/* Topography Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-4 mb-4 border-b border-sentinel-border">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-sentinel-mint" />
            <span className="font-bold text-xs uppercase tracking-wider text-sentinel-text">
              LIVE IPSEC TUNNEL TOPOGRAPHY & REAL-TIME DISSECTION
            </span>
            <span className="text-[10px] px-1.5 py-0.2 rounded border border-sentinel-mint/40 bg-sentinel-mint/10 text-sentinel-mint font-semibold">
              ESTABLISHED
            </span>
          </div>
          <div className="flex items-center gap-3 text-sentinel-text-muted text-[11px]">
            <span>TX: <strong className="text-sentinel-text">14.8 Mbps</strong></span>
            <span>RTT: <strong className="text-sentinel-text">4.2ms</strong></span>
            <Link href="/dashboard/sessions" className="text-sentinel-copper hover:underline flex items-center gap-1">
              <span>Session Analysis</span>
              <ExternalLink className="w-3 h-3" />
            </Link>
          </div>
        </div>

        {/* 3-Box Topography Layout */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-center">
          {/* Initiator Box */}
          <div className="lg:col-span-3 p-3.5 rounded-lg border border-sentinel-border bg-[#151719]">
            <div className="flex items-center justify-between text-[10px] text-sentinel-text-muted mb-1">
              <span className="uppercase font-semibold">INITIATOR</span>
              <span className="text-sentinel-mint flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-sentinel-mint animate-pulse" />
                <span>ONLINE</span>
              </span>
            </div>
            <div className="font-bold text-sm text-sentinel-text mb-1">
              CLIENT (Security Domain A)
            </div>
            <div className="text-sentinel-copper font-bold text-xs mb-2">
              10.0.1.12:500
            </div>
            <div className="text-[10px] text-sentinel-text-muted space-y-0.5 border-t border-sentinel-border/50 pt-2">
              <div>ID: fqdn:client.delhi.ntro.in</div>
              <div className="text-sentinel-mint">NAT-T: ENABLED (PORT 4500 FLOW)</div>
            </div>
          </div>

          {/* Central IPsec Tunnel Envelope */}
          <div className="lg:col-span-6 p-4 rounded-lg border border-dashed border-sentinel-copper/70 bg-[#0B0C0D] relative">
            <div className="flex items-center justify-between text-[10px] text-sentinel-text-muted mb-2">
              <span className="text-sentinel-copper font-bold uppercase tracking-wider flex items-center gap-1">
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>IPSEC SECURE TUNNEL ENVELOPE (RFC 4303)</span>
              </span>
              <span className="font-mono text-sentinel-text-muted">
                SPI_IN: 0x9b4a2e1f / SPI_OUT: 0x3c8d197a
              </span>
            </div>

            {/* Tunnel Tabs */}
            <div className="flex items-center gap-2 mb-3">
              <button
                onClick={() => setSelectedTunnelTab('ESP1')}
                className={`px-2.5 py-1 rounded text-[10px] font-bold transition-colors ${
                  selectedTunnelTab === 'ESP1'
                    ? 'border border-sentinel-copper bg-sentinel-copper/15 text-sentinel-copper'
                    : 'border border-sentinel-border bg-[#151719] text-sentinel-text-muted'
                }`}
              >
                ● ESP #18419
              </button>
              <button
                onClick={() => setSelectedTunnelTab('IKE')}
                className={`px-2.5 py-1 rounded text-[10px] font-bold transition-colors ${
                  selectedTunnelTab === 'IKE'
                    ? 'border border-sentinel-copper bg-sentinel-copper/15 text-sentinel-copper'
                    : 'border border-sentinel-border bg-[#151719] text-sentinel-text-muted'
                }`}
              >
                ● IKEv2 #36
              </button>
              <button
                onClick={() => setSelectedTunnelTab('ESP2')}
                className={`px-2.5 py-1 rounded text-[10px] font-bold transition-colors ${
                  selectedTunnelTab === 'ESP2'
                    ? 'border border-sentinel-copper bg-sentinel-copper/15 text-sentinel-copper'
                    : 'border border-sentinel-border bg-[#151719] text-sentinel-text-muted'
                }`}
              >
                ● ESP #18420
              </button>
            </div>

            {/* Cryptographic Envelope Attributes Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center text-[10px] mb-3">
              <div className="p-2 rounded border border-sentinel-border bg-[#151719]">
                <div className="text-sentinel-text-muted">ENCRYPTION</div>
                <div className="font-bold text-sentinel-text mt-0.5">AES-256-GCM</div>
              </div>
              <div className="p-2 rounded border border-sentinel-border bg-[#151719]">
                <div className="text-sentinel-text-muted">DIFFIE-HELLMAN</div>
                <div className="font-bold text-sentinel-text mt-0.5">DH GROUP 19</div>
              </div>
              <div className="p-2 rounded border border-sentinel-border bg-[#151719]">
                <div className="text-sentinel-text-muted">FORWARD SECRECY</div>
                <div className="font-bold text-sentinel-mint mt-0.5">PFS ENABLED</div>
              </div>
              <div className="p-2 rounded border border-sentinel-border bg-[#151719]">
                <div className="text-sentinel-text-muted">PROTOCOL LAYER</div>
                <div className="font-bold text-sentinel-copper mt-0.5">ESP (UDP 4500)</div>
              </div>
            </div>

            <div className="text-[10px] text-center text-sentinel-text-muted font-mono">
              [ Click tunnel envelope to inspect session telemetry & cryptographic state ]
            </div>
          </div>

          {/* Responder Box */}
          <div className="lg:col-span-3 p-3.5 rounded-lg border border-sentinel-border bg-[#151719] text-right">
            <div className="flex items-center justify-between text-[10px] text-sentinel-text-muted mb-1">
              <span className="text-sentinel-mint flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-sentinel-mint animate-pulse" />
                <span>SYNCHRONIZED</span>
              </span>
              <span className="uppercase font-semibold">RESPONDER</span>
            </div>
            <div className="font-bold text-sm text-sentinel-text mb-1">
              GATEWAY (HQ Core Border)
            </div>
            <div className="text-sentinel-copper font-bold text-xs mb-2">
              10.0.2.20:4500
            </div>
            <div className="text-[10px] text-sentinel-text-muted space-y-0.5 border-t border-sentinel-border/50 pt-2">
              <div>ID: ip:10.0.2.20</div>
              <div className="text-sentinel-text">strongSwan 5.9.11 (STRICT-OE)</div>
            </div>
          </div>
        </div>
      </div>

      {/* ==================================================== */}
      {/* 5. ROW 4: PIPELINE EXECUTION NTRO-26160              */}
      {/* ==================================================== */}
      <div className="p-5 rounded-xl border border-sentinel-border bg-[#101214] font-mono text-xs">
        <div className="flex items-center justify-between pb-3 mb-4 border-b border-sentinel-border">
          <div className="flex items-center gap-2">
            <span className="text-[10px] px-1.5 py-0.2 rounded border border-sentinel-copper text-sentinel-copper font-bold">
              01
            </span>
            <span className="font-bold text-xs uppercase tracking-wider text-sentinel-text">
              DETERMINISTIC MULTI-STAGE ANALYSIS ENGINE PIPELINE
            </span>
            <span className="text-[10px] text-sentinel-text-muted">
              NTRO-26160
            </span>
          </div>
          <div className="flex items-center gap-2 text-[11px] text-sentinel-mint font-semibold">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>EXECUTION TIME: 412ms | STAGE 7 OF 8 ACTIVE</span>
          </div>
        </div>

        {/* 8 Stages Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-2.5 mb-4">
          {pipelineStages.map((stage, i) => (
            <div
              key={i}
              className={`p-2.5 rounded border text-center transition-all ${
                stage.status === 'ACTIVE'
                  ? 'border-sentinel-copper bg-sentinel-copper/15 shadow-sm'
                  : stage.status === 'COMPLETED'
                  ? 'border-sentinel-border bg-[#151719]'
                  : 'border-sentinel-border/50 bg-[#0B0C0D] opacity-60'
              }`}
            >
              <div className="flex items-center justify-center gap-1 mb-1">
                <span
                  className={`w-1.5 h-1.5 rounded-full ${
                    stage.status === 'ACTIVE'
                      ? 'bg-sentinel-copper animate-ping'
                      : stage.status === 'COMPLETED'
                      ? 'bg-sentinel-mint'
                      : 'bg-sentinel-border'
                  }`}
                />
                <span
                  className={`text-[10px] font-bold ${
                    stage.status === 'ACTIVE' ? 'text-sentinel-copper' : 'text-sentinel-text'
                  }`}
                >
                  {stage.step}. {stage.name}
                </span>
              </div>
              <div className="text-[10px] text-sentinel-text truncate font-medium">
                {stage.detail}
              </div>
              <div className="text-[9px] text-sentinel-text-muted truncate mt-0.5">
                {stage.meta}
              </div>
            </div>
          ))}
        </div>

        {/* Terminal Execution Snippet */}
        <div className="p-3 rounded border border-sentinel-border bg-[#0B0C0D] text-[11px] space-y-1 text-sentinel-text-muted">
          <div>
            [04:18:21.102] <span className="text-sentinel-copper">PARSER</span>: Matched IKE_SA_INIT exchange. Proposal 01: ENCR_AES_GCM_256, PRF_HMAC_SHA384, DH_GROUP_19.
          </div>
          <div>
            [04:18:21.829] <span className="text-sentinel-warning">RFC_ENGINE</span>: Rule RFC-C-027 triggered on CREATE_CHILD_SA (ReRekey12): Key exchange payload KEs absent.
          </div>
          <div>
            [04:18:22.001] <span className="text-sentinel-mint">ML_CLASSIFY</span>: High-entropy burst payload pattern matches encoded H.264 VBR streaming profile (1.2 Mbps).
          </div>
        </div>
      </div>

      {/* ==================================================== */}
      {/* 6. ROW 5: ACTIVE FINDINGS & MONITORED SESSIONS       */}
      {/* ==================================================== */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 font-mono text-xs">
        {/* Left: Active Policy & Security Findings (3) */}
        <div className="lg:col-span-7 p-5 rounded-xl border border-sentinel-border bg-[#101214]">
          <div className="flex items-center justify-between pb-3 mb-4 border-b border-sentinel-border">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-sentinel-warning" />
              <span className="font-bold text-xs uppercase tracking-wider text-sentinel-text">
                ACTIVE POLICY & SECURITY FINDINGS (3)
              </span>
            </div>
            <span className="text-[10px] text-sentinel-text-muted">
              Session Context: <strong className="text-sentinel-copper">IPSEC-00421</strong>
            </span>
          </div>

          <div className="space-y-3">
            {findings.map((finding) => (
              <div
                key={finding.id}
                className="p-3.5 rounded-lg border border-sentinel-border bg-[#151719] hover:border-sentinel-copper/40 transition-colors"
              >
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase ${
                        finding.severity === 'HIGH'
                          ? 'bg-sentinel-critical/15 text-sentinel-critical border border-sentinel-critical/30'
                          : finding.severity === 'MEDIUM'
                          ? 'bg-sentinel-warning/15 text-sentinel-warning border border-sentinel-warning/30'
                          : 'bg-sentinel-info/15 text-sentinel-info border border-sentinel-info/30'
                      }`}
                    >
                      {finding.severity}
                    </span>
                    <span className="font-bold text-xs text-sentinel-text">
                      {finding.title}
                    </span>
                  </div>
                  <span className="text-[10px] text-sentinel-copper font-bold px-1.5 py-0.5 rounded border border-sentinel-copper/40 bg-sentinel-copper/10">
                    {finding.ruleCode}
                  </span>
                </div>

                <p className="text-[11px] text-sentinel-text-muted leading-relaxed mb-2 font-sans">
                  {finding.description}
                </p>

                <div className="p-2 rounded border border-sentinel-border/70 bg-[#0B0C0D] text-[10px] flex items-center justify-between text-sentinel-text-muted">
                  <span className="truncate">
                    remediation: <code className="text-sentinel-copper">{finding.remediation}</code>
                  </span>
                  <span className="shrink-0 text-sentinel-text-muted ml-2">
                    Engine: {finding.engine}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Monitored Tunnel Sessions Table */}
        <div className="lg:col-span-5 p-5 rounded-xl border border-sentinel-border bg-[#101214] flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 mb-4 border-b border-sentinel-border">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-sentinel-copper" />
                <span className="font-bold text-xs uppercase tracking-wider text-sentinel-text">
                  MONITORED TUNNEL SESSIONS
                </span>
              </div>
              <span className="text-[10px] text-sentinel-mint">4 Active Feeds</span>
            </div>

            <div className="space-y-2.5">
              {sessions.map((sess) => (
                <div
                  key={sess.id}
                  className={`p-3 rounded-lg border transition-all ${
                    sess.status === 'ACTIVE'
                      ? 'border-sentinel-copper/60 bg-[#151719]'
                      : sess.status === 'CRIT'
                      ? 'border-sentinel-critical/50 bg-sentinel-critical/5'
                      : 'border-sentinel-border bg-[#151719]'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-bold text-xs text-sentinel-text flex items-center gap-1.5">
                      <span
                        className={`w-1.5 h-1.5 rounded-full ${
                          sess.status === 'CRIT'
                            ? 'bg-sentinel-critical'
                            : sess.status === 'ACTIVE'
                            ? 'bg-sentinel-copper animate-pulse'
                            : 'bg-sentinel-mint'
                        }`}
                      />
                      <span>{sess.id}</span>
                    </span>
                    <span
                      className={`text-[9px] px-1.5 py-0.5 rounded font-bold ${
                        sess.status === 'CRIT'
                          ? 'bg-sentinel-critical text-white'
                          : 'bg-sentinel-border/50 text-sentinel-text'
                      }`}
                    >
                      SCORE: {sess.riskScore}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-1 text-[10px] text-sentinel-text-muted mt-1.5">
                    <div>
                      Cipher: <span className="text-sentinel-text">{sess.cipher}</span>
                    </div>
                    <div>
                      Traffic: <span className="text-sentinel-copper">{sess.trafficType}</span>
                    </div>
                    <div>
                      PFS: <span className={sess.pfs === 'WARN' ? 'text-sentinel-warning' : sess.pfs === 'NO' ? 'text-sentinel-critical' : 'text-sentinel-mint'}>{sess.pfs}</span>
                    </div>
                    <div>
                      Frames: <span className="text-sentinel-text">{sess.packets.toLocaleString()} pkts</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-sentinel-border/70 text-right">
            <Link
              href="/dashboard/sessions"
              className="text-sentinel-copper hover:underline text-[11px] inline-flex items-center gap-1"
            >
              <span>View All 24 Active Sessions</span>
              <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
        </div>
      </div>

      {/* ==================================================== */}
      {/* 7. ROW 6: RAG GROUNDED INTELLIGENCE SYNTHESIS        */}
      {/* ==================================================== */}
      <div className="p-5 rounded-xl border border-sentinel-border bg-[#101214] font-mono text-xs">
        <div className="flex items-center justify-between pb-3 mb-3 border-b border-sentinel-border">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-sentinel-copper" />
            <span className="font-bold text-xs uppercase tracking-wider text-sentinel-text">
              RAG GROUNDED INTELLIGENCE SYNTHESIS
            </span>
          </div>
          <span className="text-[10px] font-bold px-2 py-0.5 rounded border border-sentinel-copper/50 bg-sentinel-copper/10 text-sentinel-copper">
            EVIDENCE VERIFIED
          </span>
        </div>

        <p className="text-xs text-sentinel-text leading-relaxed font-sans mb-4">
          The tunnel session <strong className="text-sentinel-copper font-mono">IPSEC-00421</strong> demonstrates robust modern classical cryptography with Suite-B compliant AES-256-GCM and Diffie-Hellman Group 19. However, the operational posture is degraded due to two specific non-crypto absences: absence of PFS in child renegotiation creates retrospection compromise risks if the parent IKE SA is ever broken, and lack of TFC padding leaks video telemetry to intermediate wire-taps. Recommended immediate action: recur configuration update to swanctl.conf to restrict lifetime to 7200s and mandate PFS key exchange.
        </p>

        <div className="p-3 rounded border border-sentinel-border bg-[#0B0C0D] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-[11px]">
          <div className="text-sentinel-text-muted flex items-center gap-2">
            <span className="text-sentinel-mint">● Deterministic Anchor:</span>
            <span>RFC 7296 §1.3 — NTRO Baseline Clause 4.2</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopyDiff}
              className="px-2.5 py-1 rounded border border-sentinel-border bg-[#151719] hover:border-sentinel-copper/50 text-sentinel-text transition-colors flex items-center gap-1.5 text-[10px]"
            >
              <Copy className="w-3 h-3 text-sentinel-copper" />
              <span>{copiedDiff ? 'Copied config diff!' : 'copy config diff ->'}</span>
            </button>
            <button className="px-2.5 py-1 rounded border border-sentinel-copper bg-sentinel-copper text-white dark:text-[#0B0C0D] font-bold hover:bg-sentinel-copper/90 transition-colors text-[10px]">
              Execute Patch
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
