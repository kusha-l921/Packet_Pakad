'use client';

import React, { useState } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import { MetricStrip } from '@/components/dashboard/MetricStrip';
import { SecurityScore } from '@/components/dashboard/SecurityScore';
import { SecurityPosture } from '@/components/dashboard/SecurityPosture';
import { TunnelVisualization } from '@/components/dashboard/TunnelVisualization';
import { SessionTable } from '@/components/dashboard/SessionTable';
import { AnalysisPipeline } from '@/components/analysis/AnalysisPipeline';
import { mockSecurityScore } from '@/data/dashboard';
import { mockSessions } from '@/data/sessions';
import { mockComplianceFindings } from '@/data/findings';
import {
  Download,
  RotateCcw,
  FileSpreadsheet,
  AlertTriangle,
  ChevronRight,
  BookOpen,
  ArrowUpRight,
  Radio,
} from 'lucide-react';
import Link from 'next/link';

export default function DashboardPage() {
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);

  const toggleFinding = (id: string) => {
    setExpandedFinding(expandedFinding === id ? null : id);
  };

  return (
    <AppShell>
      <div className="space-y-6 max-w-7xl mx-auto">
        {/* Page Title & Action Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-1">
          <div>
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-sentinel-copper" />
              <h1 className="font-mono-tech text-base md:text-lg font-bold tracking-wider text-sentinel-text uppercase">
                Security Overview Dashboard
              </h1>
            </div>
            <p className="text-xs text-sentinel-muted mt-0.5">
              NTRO Benchmark Problem Statement 26160 • Sovereign Defense Cryptographic Assessment
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Link
              href="/capture"
              className="flex items-center gap-1.5 px-3 py-1.5 bg-sentinel-secondary border border-sentinel-border hover:border-sentinel-copper text-sentinel-text font-mono-tech text-xs rounded transition-colors"
            >
              <Radio className="w-3.5 h-3.5 text-sentinel-copper" />
              Live Stream
            </Link>
            <button
              onClick={() => {
                const blob = new Blob([JSON.stringify(mockSessions[0], null, 2)], {
                  type: 'application/json',
                });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'session_IPSEC-00421.json';
                a.click();
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-sentinel-secondary border border-sentinel-border hover:border-sentinel-copper text-sentinel-muted hover:text-sentinel-text font-mono-tech text-xs rounded transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              Export Session JSON
            </button>
            <Link
              href="/reports"
              className="flex items-center gap-1.5 px-3 py-1.5 bg-sentinel-copper text-sentinel-bg font-mono-tech text-xs font-semibold rounded hover:bg-sentinel-copperHover transition-colors"
            >
              <FileSpreadsheet className="w-3.5 h-3.5" />
              Exec Report
            </Link>
          </div>
        </div>

        {/* Structured Metric Strip */}
        <MetricStrip scoreData={mockSecurityScore} />

        {/* Security Posture Top Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <SecurityScore scoreData={mockSecurityScore} />
          <SecurityPosture posture={mockSecurityScore.posture} />
        </div>

        {/* IPsec Tunnel Interactive Topography Visualization */}
        <TunnelVisualization session={mockSessions[0]} />

        {/* Multi-stage Analysis Pipeline */}
        <AnalysisPipeline isRunning={false} />

        {/* Mid-Grid: Active Findings Feed & Monitored Sessions Table */}
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
          {/* Active Findings Feed (5 cols on xl) */}
          <div className="xl:col-span-5 panel-technical p-4 rounded-lg flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-3 border-b border-sentinel-border mb-3">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-sentinel-warning" />
                  <span className="font-mono-tech text-xs font-semibold uppercase tracking-wider text-sentinel-text">
                    Active Security Findings
                  </span>
                </div>
                <Link
                  href="/threats"
                  className="text-[11px] font-mono-tech text-sentinel-copper hover:underline flex items-center gap-1"
                >
                  Threat Matrix <ArrowUpRight className="w-3 h-3" />
                </Link>
              </div>

              <div className="space-y-2.5">
                {mockComplianceFindings.slice(1, 4).map((f) => (
                  <div
                    key={f.id}
                    className="p-3 rounded border border-sentinel-border bg-sentinel-secondary/30 hover:border-sentinel-copper/50 transition-colors cursor-pointer"
                    onClick={() => toggleFinding(f.id)}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-2">
                          <span className="font-mono-tech text-[10px] text-sentinel-copper font-bold">
                            {f.ruleId}
                          </span>
                          <span className="font-mono-tech text-[9px] px-1 py-0.2 rounded bg-sentinel-elevated text-sentinel-muted">
                            {f.rfcRef}
                          </span>
                        </div>
                        <div className="text-xs font-medium text-sentinel-text">
                          {f.description}
                        </div>
                      </div>
                      <ChevronRight
                        className={`w-3.5 h-3.5 text-sentinel-muted transition-transform ${
                          expandedFinding === f.id ? 'rotate-90' : ''
                        }`}
                      />
                    </div>

                    {expandedFinding === f.id && (
                      <div className="mt-3 pt-2.5 border-t border-sentinel-border text-xs space-y-2 font-mono-tech">
                        <div>
                          <span className="text-sentinel-muted text-[10px] block uppercase">
                            Evidence:
                          </span>
                          <span className="text-sentinel-text text-[11px]">
                            {f.evidence}
                          </span>
                        </div>
                        <div>
                          <span className="text-sentinel-muted text-[10px] block uppercase">
                            Remediation:
                          </span>
                          <span className="text-sentinel-mint text-[11px]">
                            {f.recommendation}
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            <div className="pt-3 border-t border-sentinel-border mt-3 text-[11px] font-mono-tech text-sentinel-muted flex items-center justify-between">
              <span>Rule Engine: 24 active rules checked</span>
              <span className="text-sentinel-copper font-medium">87% Passed</span>
            </div>
          </div>

          {/* Monitored Sessions Table (7 cols on xl) */}
          <div className="xl:col-span-7">
            <SessionTable sessions={mockSessions} />
          </div>
        </div>

        {/* Bottom Panel: Evidence Grounded RAG Synthesis Banner */}
        <div className="panel-technical p-4 rounded-lg bg-sentinel-elevated/40 border border-sentinel-border flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="space-y-1 max-w-3xl">
            <div className="flex items-center gap-2 text-xs font-mono-tech text-sentinel-mint">
              <BookOpen className="w-4 h-4 text-sentinel-copper" />
              <span className="font-semibold uppercase tracking-wider">
                Grounded Security Analysis (Session IPSEC-00421)
              </span>
            </div>
            <p className="text-xs text-sentinel-muted leading-relaxed font-sans">
              Autonomous analysis confirms cryptographic cipher robustness (AES-256-GCM), but detects a critical Child-SA rekeying configuration error omitting ephemeral DH keys, accompanied by unpadded 33.3ms video traffic cadence exposing side-channel telepresence patterns.
            </p>
          </div>
          <Link
            href="/sessions/IPSEC-00421"
            className="flex-shrink-0 px-3.5 py-2 rounded bg-sentinel-secondary border border-sentinel-border hover:border-sentinel-copper text-xs font-mono-tech text-sentinel-text hover:text-sentinel-copper transition-colors"
          >
            Inspect Technical Evidence →
          </Link>
        </div>
      </div>
    </AppShell>
  );
}
