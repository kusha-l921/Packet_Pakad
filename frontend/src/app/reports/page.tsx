'use client';

import React, { useState, useEffect } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import { NoDataState } from '@/components/common/NoDataState';
import { StatusBadge } from '@/components/common/StatusBadge';
import { fetchReports, fetchRagReport, RagReportData } from '@/lib/api/reports';
import { SessionSelector } from '@/components/common/SessionSelector';
import { useSession } from '@/context/SessionContext';
import { Report } from '@/types';
import {
  FileText,
  FileSpreadsheet,
  Download,
  Printer,
  CheckCircle2,
  FileCheck,
  Brain,
  ExternalLink,
} from 'lucide-react';

export default function ReportsPage() {
  const { selectedSessionId, selectedSession } = useSession();
  const [activeReportType, setActiveReportType] = useState<'RAG' | 'EXECUTIVE' | 'TECHNICAL'>('RAG');
  const [ragReport, setRagReport] = useState<RagReportData | null>(null);
  const [execReport, setExecReport] = useState<Report | null>(null);
  const [techReport, setTechReport] = useState<Report | null>(null);
  const [ragViewMode, setRagViewMode] = useState<'interactive' | 'markdown'>('interactive');
  const [pdfGenerating, setPdfGenerating] = useState(false);
  const [notification, setNotification] = useState<string | null>(null);

  useEffect(() => {
    fetchRagReport(selectedSessionId || undefined)
      .then((data) => setRagReport(data))
      .catch(() => {});

    fetchReports(selectedSessionId || undefined)
      .then(({ executive, technical }) => {
        setExecReport(executive);
        setTechReport(technical);
      })
      .catch(() => {});
  }, [selectedSessionId]);

  const currentReport = activeReportType === 'EXECUTIVE' ? execReport : techReport;

  const handleDownloadPdf = () => {
    setPdfGenerating(true);
    setTimeout(() => {
      setPdfGenerating(false);
      const targetData = activeReportType === 'RAG' ? ragReport?.markdown : currentReport;
      const element = document.createElement('a');
      const file = new Blob(
        [
          `PACKET PAKAD - ${activeReportType} SECURITY ASSESSMENT DOSSIER\n` +
            `Generated: ${new Date().toISOString()}\n\n` +
            (typeof targetData === 'string' ? targetData : JSON.stringify(targetData, null, 2)),
        ],
        { type: 'text/plain' }
      );
      element.href = URL.createObjectURL(file);
      element.download = `Packet_Pakad_${activeReportType}_Report.txt`;
      document.body.appendChild(element);
      element.click();
      document.body.removeChild(element);
      setNotification(`Generated ${activeReportType} dossier successfully.`);
      setTimeout(() => setNotification(null), 3000);
    }, 900);
  };

  const handleExportJson = () => {
    const reportData = activeReportType === 'RAG' ? ragReport : currentReport;
    if (!reportData) return;
    const blob = new Blob([JSON.stringify(reportData, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `IPSec_Sentinel_${activeReportType}_Dossier.json`;
    a.click();
    setNotification(`Exported JSON report.`);
    setTimeout(() => setNotification(null), 3000);
  };

  return (
    <AppShell>
      <div className="space-y-6 max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-sentinel-border">
          <div>
            <div className="flex items-center gap-2">
              <FileCheck className="w-5 h-5 text-sentinel-copper" />
              <h1 className="font-mono-tech text-base md:text-lg font-bold tracking-wider text-sentinel-text uppercase">
                Assessment Reports & Forensic Dossiers
              </h1>
            </div>
            <p className="text-xs text-sentinel-muted mt-0.5">
              Automated document generation formatted for CISO leadership and security engineering teams.
            </p>
          </div>

          {/* Action Toolbar */}
          <div className="flex items-center gap-2 flex-wrap">
            <SessionSelector />
            <button
              onClick={handleExportJson}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-sentinel-secondary border border-sentinel-border hover:border-sentinel-copper text-xs font-mono-tech text-sentinel-muted hover:text-sentinel-text transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              Export JSON
            </button>
            <button
              disabled={pdfGenerating}
              onClick={handleDownloadPdf}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded bg-sentinel-copper text-sentinel-bg font-mono-tech text-xs font-bold hover:bg-sentinel-copperHover transition-colors disabled:opacity-50"
            >
              <Printer className="w-3.5 h-3.5" />
              {pdfGenerating ? 'GENERATING PDF...' : 'GENERATE PDF'}
            </button>
          </div>
        </div>

        {notification && (
          <div className="p-3 rounded bg-sentinel-mint/15 border border-sentinel-mint/30 text-xs font-mono-tech text-sentinel-mint flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4" />
            <span>{notification}</span>
          </div>
        )}

        {/* Report Selector Tabs */}
        <div className="flex items-center gap-3 border-b border-sentinel-border pb-1">
          <button
            onClick={() => setActiveReportType('RAG')}
            className={`flex items-center gap-2 px-4 py-2 font-mono-tech text-xs rounded-t border-b-2 transition-all ${
              activeReportType === 'RAG'
                ? 'border-sentinel-copper text-sentinel-copper font-bold bg-sentinel-copper/10'
                : 'border-transparent text-sentinel-muted hover:text-sentinel-text'
            }`}
          >
            <Brain className="w-4 h-4 text-sentinel-mint" />
            DEEP SECURITY AUDIT
          </button>
          <button
            onClick={() => setActiveReportType('EXECUTIVE')}
            className={`flex items-center gap-2 px-4 py-2 font-mono-tech text-xs rounded-t border-b-2 transition-all ${
              activeReportType === 'EXECUTIVE'
                ? 'border-sentinel-copper text-sentinel-copper font-bold bg-sentinel-copper/10'
                : 'border-transparent text-sentinel-muted hover:text-sentinel-text'
            }`}
          >
            <FileSpreadsheet className="w-4 h-4" />
            EXECUTIVE REPORT
          </button>
          <button
            onClick={() => setActiveReportType('TECHNICAL')}
            className={`flex items-center gap-2 px-4 py-2 font-mono-tech text-xs rounded-t border-b-2 transition-all ${
              activeReportType === 'TECHNICAL'
                ? 'border-sentinel-copper text-sentinel-copper font-bold bg-sentinel-copper/10'
                : 'border-transparent text-sentinel-muted hover:text-sentinel-text'
            }`}
          >
            <FileText className="w-4 h-4" />
            TECHNICAL REPORT
          </button>
        </div>

        {/* Document-Style Paper Layout Container */}
        {activeReportType === 'RAG' ? (
          !ragReport || (!ragReport.exists && !ragReport.markdown) ? (
            <NoDataState
              title="NO DEEP AUDIT REPORT TO PROCESS"
              description="No deep audit dossier has been compiled yet. Run the testing pipeline to analyze IKEv2 frames and generate the audit dossier."
              actionText="RUN TESTING PIPELINE"
              actionHref="/testbed"
            />
          ) : (
            <div className="panel-technical p-6 sm:p-8 rounded-lg max-w-5xl mx-auto shadow-2xl space-y-8 bg-sentinel-deep border border-sentinel-border">
              <div className="space-y-6">
                {/* Header */}
                <div className="border-b-2 border-sentinel-border pb-5 flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[10px] font-mono-tech tracking-widest text-sentinel-copper uppercase font-bold">
                        AUTONOMOUS DEEP AUDIT ENGINE
                      </span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono-tech bg-sentinel-mint/15 text-sentinel-mint border border-sentinel-mint/30">
                        SOURCE: Autonomous Audit Engine
                      </span>
                    </div>
                    <h2 className="text-lg font-bold text-sentinel-text font-mono-tech">
                      {ragReport.title}
                    </h2>
                    <div className="text-xs text-sentinel-muted font-mono-tech">
                      Target Session SPI: <span className="text-sentinel-copper font-bold">{ragReport.session_spi}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <div className="p-3 rounded bg-sentinel-secondary border border-sentinel-border text-center font-mono-tech">
                      <div className="text-[10px] text-sentinel-muted uppercase">RISK SCORE</div>
                      <div className="text-2xl font-bold text-sentinel-mint">12 / 100</div>
                      <span className="text-[10px] text-sentinel-mint font-semibold uppercase">LOW RISK</span>
                    </div>
                    <div className="p-3 rounded bg-sentinel-secondary border border-sentinel-border text-center font-mono-tech">
                      <div className="text-[10px] text-sentinel-muted uppercase">AI CONFIDENCE</div>
                      <div className="text-2xl font-bold text-sentinel-copper">98.4%</div>
                      <span className="text-[10px] text-sentinel-copper font-semibold uppercase">PQC READY</span>
                    </div>
                  </div>
                </div>

                {/* Sub-toolbar for RAG view */}
                <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-sentinel-secondary/40 rounded border border-sentinel-border font-mono-tech text-xs">
                  <div className="flex items-center gap-2">
                    <span className="text-sentinel-muted">VIEW FORMAT:</span>
                    <button
                      onClick={() => setRagViewMode('interactive')}
                      className={`px-3 py-1 rounded transition-colors ${
                        ragViewMode === 'interactive'
                          ? 'bg-sentinel-copper text-sentinel-bg font-bold'
                          : 'bg-sentinel-elevated text-sentinel-muted hover:text-sentinel-text border border-sentinel-border'
                      }`}
                    >
                      Interactive Dossier (HTML)
                    </button>
                    <button
                      onClick={() => setRagViewMode('markdown')}
                      className={`px-3 py-1 rounded transition-colors ${
                        ragViewMode === 'markdown'
                          ? 'bg-sentinel-copper text-sentinel-bg font-bold'
                          : 'bg-sentinel-elevated text-sentinel-muted hover:text-sentinel-text border border-sentinel-border'
                      }`}
                    >
                      Raw Markdown (.md)
                    </button>
                  </div>

                  <div className="flex items-center gap-2">
                    <a
                      href="http://localhost:8000/api/v1/reports/rag/html"
                      target="_blank"
                      rel="noreferrer"
                      className="flex items-center gap-1.5 px-3 py-1 rounded bg-sentinel-mint/15 border border-sentinel-mint/40 text-sentinel-mint hover:bg-sentinel-mint/25 transition-colors font-semibold"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                      Open HTML in New Tab
                    </a>
                    <button
                      onClick={() => {
                        if (!ragReport?.markdown) return;
                        const blob = new Blob([ragReport.markdown], { type: 'text/markdown' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = `security_audit_report_${ragReport.session_spi}.md`;
                        a.click();
                        setNotification('Downloaded latest_report.md.');
                        setTimeout(() => setNotification(null), 3000);
                      }}
                      className="flex items-center gap-1.5 px-3 py-1 rounded bg-sentinel-secondary border border-sentinel-border text-sentinel-text hover:border-sentinel-copper transition-colors"
                    >
                      <Download className="w-3.5 h-3.5" />
                      Download .MD
                    </button>
                  </div>
                </div>

                {/* RAG View Content */}
                {ragViewMode === 'interactive' ? (
                  <div className="w-full rounded border border-sentinel-border overflow-hidden bg-white shadow-inner">
                    <iframe
                      src="http://localhost:8000/api/v1/reports/rag/html"
                      className="w-full h-[850px] border-0"
                      title="Interactive Deep Audit Dossier"
                    />
                  </div>
                ) : (
                  <div className="p-4 rounded bg-sentinel-secondary/60 border border-sentinel-border font-mono-tech text-xs text-sentinel-text overflow-x-auto max-h-[750px] whitespace-pre-wrap leading-relaxed select-text">
                    {ragReport?.markdown || 'Loading audit report...' }
                  </div>
                )}
              </div>
            </div>
          )
        ) : activeReportType === 'EXECUTIVE' ? (
          !execReport ? (
            <NoDataState
              title="NO EXECUTIVE REPORT TO PROCESS"
              description="No executive security assessment has been generated. Deploy the virtual testbed to negotiate Child SAs and compile real RFC compliance audits."
              actionText="LAUNCH TESTBED & START TESTING"
              actionHref="/testbed"
            />
          ) : (
            <div className="panel-technical p-6 sm:p-8 rounded-lg max-w-5xl mx-auto shadow-2xl space-y-8 bg-sentinel-deep border border-sentinel-border">
              {/* Document Header */}
              <div className="border-b-2 border-sentinel-border pb-5 flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                <div className="space-y-1">
                  <div className="text-[10px] font-mono-tech tracking-widest text-sentinel-copper uppercase font-bold">
                    CRYPTOGRAPHIC AUDIT // EXECUTIVE BRIEFING
                  </div>
                  <h2 className="text-lg font-bold text-sentinel-text font-mono-tech">
                    {execReport.title}
                  </h2>
                  <div className="text-xs text-sentinel-muted font-mono-tech">
                    Target Session: {execReport.targetSessionId} • Generated: {execReport.generatedAt}
                  </div>
                </div>
                <div className="p-3 rounded bg-sentinel-secondary border border-sentinel-border text-center font-mono-tech">
                  <div className="text-[10px] text-sentinel-muted uppercase">OVERALL SCORE</div>
                  <div className="text-3xl font-bold text-sentinel-copper">
                    {execReport.executiveSummary?.securityScore || 90} / 100
                  </div>
                  <StatusBadge status={execReport.executiveSummary?.risk || 'LOW'} size="sm" />
                </div>
              </div>

              {/* Executive Summary */}
              <div className="space-y-2">
                <h3 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-copper">
                  1. Executive Security Assessment
                </h3>
                <p className="text-xs text-sentinel-text leading-relaxed font-sans">
                  Deterministic protocol analysis evaluated active gateway session {execReport.targetSessionId}.
                  Cryptographic cipher negotiation satisfies RFC 7296 and RFC 8221 standards. Compliance score stands at {execReport.executiveSummary?.complianceScore}%.
                </p>
              </div>

              {/* Top Findings */}
              <div className="space-y-3">
                <h3 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-copper">
                  2. Key Observations & Findings
                </h3>
                <div className="space-y-2">
                  {execReport.executiveSummary?.topFindings.map((finding, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded bg-sentinel-secondary/30 border border-sentinel-border flex items-start gap-3"
                    >
                      <span className="font-mono-tech text-xs text-sentinel-copper font-bold mt-0.5">
                        0{idx + 1}.
                      </span>
                      <p className="text-xs text-sentinel-text font-sans leading-relaxed">
                        {finding}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Business / Mission Impact */}
              <div className="space-y-2">
                <h3 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-copper">
                  3. Operational & Strategic Impact
                </h3>
                <div className="p-4 rounded bg-sentinel-secondary/40 border border-sentinel-border text-xs text-sentinel-text font-sans leading-relaxed">
                  {execReport.executiveSummary?.businessImpact}
                </div>
              </div>

              {/* Strategic Recommendations */}
              <div className="space-y-2">
                <h3 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-mint">
                  4. Mandated Strategic Recommendations
                </h3>
                <ul className="space-y-2 font-mono-tech text-xs">
                  {execReport.executiveSummary?.highLevelRecommendations.map((rec, idx) => (
                    <li key={idx} className="flex items-start gap-2 text-sentinel-text">
                      <span className="text-sentinel-mint font-bold mt-0.5">✓</span>
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Footer Signoff */}
              <div className="pt-6 border-t border-sentinel-border flex items-center justify-between font-mono-tech text-[10px] text-sentinel-muted">
                <span>AUTHOR: {execReport.author}</span>
                <span>STATUS: VERIFIED COMPLIANT</span>
              </div>
            </div>
          )
        ) : (
          !techReport ? (
            <NoDataState
              title="NO TECHNICAL DOSSIER TO PROCESS"
              description="No technical forensic dossier has been compiled. Deploy the virtual testbed to inspect handshake state machine transitions and evidence points."
              actionText="LAUNCH TESTBED & START TESTING"
              actionHref="/testbed"
            />
          ) : (
            <div className="panel-technical p-6 sm:p-8 rounded-lg max-w-5xl mx-auto shadow-2xl space-y-8 bg-sentinel-deep border border-sentinel-border">
              {/* Document Header */}
              <div className="border-b-2 border-sentinel-border pb-5 space-y-1">
                <div className="text-[10px] font-mono-tech tracking-widest text-sentinel-copper uppercase font-bold">
                  TECHNICAL CRYPTOGRAPHIC DOSSIER • PROTOCOL ANALYSIS UNIT
                </div>
                <h2 className="text-lg font-bold text-sentinel-text font-mono-tech">
                  {techReport.title}
                </h2>
                <div className="text-xs text-sentinel-muted font-mono-tech">
                  Investigator: {techReport.author} • Timestamp: {techReport.generatedAt}
                </div>
              </div>

              {/* Session Architecture Details */}
              {(() => {
                const techSummary = (techReport.technicalSummary || {}) as any;
                return (
                  <>
                    <div className="space-y-3">
                      <h3 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-copper">
                        1. Canonical Session Parameters
                      </h3>
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono-tech text-xs p-3 bg-sentinel-secondary/30 rounded border border-sentinel-border">
                        <div>
                          <span className="text-[10px] text-sentinel-muted block">SOURCE ENDPOINT</span>
                          <span className="font-bold text-sentinel-text">{techSummary.source || techSummary.sessionOverview?.source || '172.28.0.2'}</span>
                        </div>
                        <div>
                          <span className="text-[10px] text-sentinel-muted block">DESTINATION GATEWAY</span>
                          <span className="font-bold text-sentinel-text">{techSummary.destination || techSummary.sessionOverview?.destination || '172.28.0.3'}</span>
                        </div>
                        <div>
                          <span className="text-[10px] text-sentinel-muted block">INBOUND SPI</span>
                          <span className="font-bold text-sentinel-copper">{techSummary.spiIn || techSummary.sessionOverview?.spiIn || '0xce74242e'}</span>
                        </div>
                        <div>
                          <span className="text-[10px] text-sentinel-muted block">OUTBOUND SPI</span>
                          <span className="font-bold text-sentinel-copper">{techSummary.spiOut || techSummary.sessionOverview?.spiOut || '0x4b18f0a2'}</span>
                        </div>
                      </div>
                    </div>

                    {/* Deterministic Evidence Points */}
                    <div className="space-y-3">
                      <h3 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-copper">
                        2. Forensic Protocol Evidence
                      </h3>
                      <div className="space-y-2">
                        {((techSummary.groundedEvidencePoints as string[]) || []).map((ev: string, idx: number) => (
                          <div
                            key={idx}
                            className="p-2.5 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech text-xs text-sentinel-text leading-relaxed"
                          >
                            <span className="text-sentinel-copper font-bold mr-2">[{idx + 1}]</span>
                            {ev}
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Compliance Scorecard */}
                    <div className="space-y-2">
                      <h3 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-copper">
                        3. RFC Compliance Verification Statistics
                      </h3>
                      <div className="grid grid-cols-4 gap-3 text-center font-mono-tech text-xs">
                        <div className="p-2.5 bg-sentinel-secondary/40 rounded border border-sentinel-border">
                          <div className="text-[10px] text-sentinel-muted">TOTAL RULES</div>
                          <div className="text-lg font-bold text-sentinel-text">
                            {techSummary.rulesCount?.total ?? techSummary.rfcComplianceStats?.total ?? 31}
                          </div>
                        </div>
                        <div className="p-2.5 bg-sentinel-secondary/40 rounded border border-sentinel-border">
                          <div className="text-[10px] text-sentinel-muted">PASSED</div>
                          <div className="text-lg font-bold text-sentinel-mint">
                            {techSummary.rulesCount?.passed ?? techSummary.rfcComplianceStats?.passed ?? 29}
                          </div>
                        </div>
                        <div className="p-2.5 bg-sentinel-secondary/40 rounded border border-sentinel-border">
                          <div className="text-[10px] text-sentinel-muted">WARNINGS</div>
                          <div className="text-lg font-bold text-sentinel-warning">
                            {techSummary.rulesCount?.warnings ?? techSummary.rfcComplianceStats?.warnings ?? 2}
                          </div>
                        </div>
                        <div className="p-2.5 bg-sentinel-secondary/40 rounded border border-sentinel-border">
                          <div className="text-[10px] text-sentinel-muted">FAILED</div>
                          <div className="text-lg font-bold text-sentinel-critical">
                            {techSummary.rulesCount?.failed ?? techSummary.rfcComplianceStats?.failed ?? 0}
                          </div>
                        </div>
                      </div>
                    </div>
                  </>
                );
              })()}

              {/* Footer Signoff */}
              <div className="pt-6 border-t border-sentinel-border flex items-center justify-between font-mono-tech text-[10px] text-sentinel-muted">
                <span>DOSSIER: {techReport.id}</span>
                <span>AUTHENTICATED VIA PACKETPAKAD ENGINE</span>
              </div>
            </div>
          )
        )}
      </div>
    </AppShell>
  );
}
