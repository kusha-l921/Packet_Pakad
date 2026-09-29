'use client';

import React, { useState, useEffect } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import { MetricStrip } from '@/components/dashboard/MetricStrip';
import { SecurityScore } from '@/components/dashboard/SecurityScore';
import { SecurityPosture } from '@/components/dashboard/SecurityPosture';
import { TunnelVisualization } from '@/components/dashboard/TunnelVisualization';
import { SessionTable } from '@/components/dashboard/SessionTable';
import { AnalysisPipeline } from '@/components/analysis/AnalysisPipeline';
import { SecurityScore as SecurityScoreType, ComplianceFinding, Session } from '@/types';
import { fetchCurrentSecurityScore, fetchComplianceFindings } from '@/lib/api/analysis';
import { fetchSessions } from '@/lib/api/sessions';
import { fetchTestbedStatus } from '@/lib/api/testbed';
import {
  Download,
  RotateCcw,
  FileSpreadsheet,
  AlertTriangle,
  ChevronRight,
  BookOpen,
  ArrowUpRight,
  Radio,
  Play,
  CheckCircle2,
  FileText,
  Activity,
  Layers,
  Server,
} from 'lucide-react';
import Link from 'next/link';
import { SessionSelector } from '@/components/common/SessionSelector';
import { useSession } from '@/context/SessionContext';

export default function DashboardPage() {
  const { selectedSessionId, selectedSession, sessions: contextSessions } = useSession();
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [scoreData, setScoreData] = useState<SecurityScoreType | null>(null);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [findings, setFindings] = useState<ComplianceFinding[]>([]);
  const [testbedStatus, setTestbedStatus] = useState<any>(null);

  useEffect(() => {
    const checkState = () => {
      fetchTestbedStatus()
        .then((status) => {
          setTestbedStatus(status);
        })
        .catch(() => {});

      fetchSessions()
        .then((sList) => {
          if (sList && sList.length > 0) {
            setSessions(sList);
          }
        })
        .catch(() => {});

      fetchCurrentSecurityScore(selectedSessionId || undefined)
        .then((score) => {
          if (score) setScoreData(score);
        })
        .catch(() => {});

      fetchComplianceFindings(selectedSessionId || undefined)
        .then((fList) => {
          if (fList) setFindings(fList);
        })
        .catch(() => {});
    };

    checkState();
    const timer = setInterval(checkState, 3000);
    return () => clearInterval(timer);
  }, [selectedSessionId]);

  const hasActiveData = Boolean(scoreData && (sessions.length > 0 || contextSessions.length > 0));
  const activeSession = selectedSession || sessions[0] || contextSessions[0];

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
              Automated Protocol & Cryptographic Verification Platform
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <SessionSelector />
            <Link
              href="/capture"
              className="flex items-center gap-1.5 px-3 py-1.5 bg-sentinel-secondary border border-sentinel-border hover:border-sentinel-copper text-sentinel-text font-mono-tech text-xs rounded transition-colors"
            >
              <Radio className="w-3.5 h-3.5 text-sentinel-copper" />
              Live Stream
            </Link>
            <button
              disabled={sessions.length === 0}
              onClick={() => {
                if (!sessions[0]) return;
                const blob = new Blob([JSON.stringify(sessions[0], null, 2)], {
                  type: 'application/json',
                });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `session_${sessions[0]?.id || 'active'}.json`;
                a.click();
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-sentinel-secondary border border-sentinel-border hover:border-sentinel-copper text-sentinel-muted hover:text-sentinel-text font-mono-tech text-xs rounded transition-colors disabled:opacity-50"
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

        {!hasActiveData ? (
          <div className="panel-technical p-8 sm:p-12 rounded-lg border border-sentinel-border bg-sentinel-elevated/40 space-y-6 text-center">
            {/* Cyber Sentinel Shield Animation */}
            <div className="relative w-48 h-48 sm:w-60 sm:h-60 mx-auto flex items-center justify-center select-none">
              <img
                src="/sentinel-shield.gif"
                alt="Scanning for IPsec Telemetry"
                className="w-48 h-48 sm:w-60 sm:h-60 rounded-full border border-sentinel-border/80 shadow-[0_0_30px_rgba(196,122,82,0.35)] object-cover"
              />
            </div>

            <div className="space-y-2 max-w-lg mx-auto">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sentinel-secondary border border-sentinel-border text-xs font-mono-tech text-sentinel-warning">
                <Radio className="w-3.5 h-3.5 text-sentinel-copper animate-pulse" />
                NO ACTIVE IPSEC TELEMETRY
              </div>
              <h2 className="text-lg sm:text-xl font-mono-tech font-bold text-sentinel-text uppercase tracking-wider">
                Virtual Testbed is Idle
              </h2>
              <p className="text-xs text-sentinel-muted leading-relaxed font-sans">
                No active encrypted Child SA, ESP packets, or live ISAKMP frames are currently detected.
                Start the testbed from the Testbed Generator to initiate the gateways, attach the sniffer, and generate live assessment data.
              </p>
            </div>



            {/* Action Bar */}
            <div className="flex flex-wrap items-center justify-center gap-3 pt-3">
              <Link
                href="/testbed"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 px-5 py-2.5 rounded bg-sentinel-copper hover:bg-sentinel-copperHover text-sentinel-bg font-mono-tech text-xs font-bold transition-all shadow-[0_0_20px_rgba(196,122,82,0.3)]"
              >
                <Play className="w-4 h-4 fill-current" />
                LAUNCH TESTBED & START TESTING
              </Link>
              <Link
                href="/reports"
                className="flex items-center gap-2 px-4 py-2.5 rounded bg-sentinel-secondary hover:bg-sentinel-elevated border border-sentinel-border hover:border-sentinel-copper text-sentinel-text font-mono-tech text-xs transition-colors"
              >
                <FileText className="w-4 h-4 text-sentinel-mint" />
                VIEW DEEP AUDIT REPORT
              </Link>
            </div>
          </div>
        ) : (
          scoreData && sessions.length > 0 && (
          <>
            {/* Structured Metric Strip */}
            <MetricStrip scoreData={scoreData} />

            {/* Security Posture Top Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <SecurityScore scoreData={scoreData} />
              <SecurityPosture posture={scoreData.posture} />
            </div>

            {/* IPsec Tunnel Interactive Topography Visualization */}
            {activeSession && <TunnelVisualization session={activeSession} />}

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
                    {findings.slice(0, 3).map((f) => (
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
                  <span>Rule Engine: {findings.length} active rules checked</span>
                  <span className="text-sentinel-copper font-medium">{scoreData.compliancePercentage}% Passed</span>
                </div>
              </div>

              {/* Monitored Sessions Table (7 cols on xl) */}
              <div className="xl:col-span-7">
                <SessionTable sessions={sessions} />
              </div>
            </div>

            {/* Bottom Panel: Evidence Grounded Deep Audit Synthesis Banner */}
            {activeSession && (
              <div className="panel-technical p-4 rounded-lg bg-sentinel-elevated/40 border border-sentinel-border flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                <div className="space-y-1 max-w-3xl">
                  <div className="flex items-center gap-2 text-xs font-mono-tech text-sentinel-mint">
                    <BookOpen className="w-4 h-4 text-sentinel-copper" />
                    <span className="font-semibold uppercase tracking-wider">
                      Grounded Security Analysis (Session {activeSession.id})
                    </span>
                  </div>
                  <p className="text-xs text-sentinel-muted leading-relaxed font-sans">
                    Autonomous analysis confirms cryptographic cipher robustness ({activeSession.encryption}), key exchange ({activeSession.dhGroup}). Peer endpoints {activeSession.source} ↔ {activeSession.destination}.
                  </p>
                </div>
                <Link
                  href={`/sessions/${activeSession.id}`}
                  className="flex-shrink-0 px-3.5 py-2 rounded bg-sentinel-secondary border border-sentinel-border hover:border-sentinel-copper text-xs font-mono-tech text-sentinel-text hover:text-sentinel-copper transition-colors"
                >
                  Inspect Technical Evidence →
                </Link>
              </div>
            )}
          </>
          )
        )}
      </div>
    </AppShell>
  );
}
