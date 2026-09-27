'use client';

import React, { useState } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import { mockExecutiveReport, mockTechnicalReport } from '@/data/reports';
import { StatusBadge } from '@/components/common/StatusBadge';
import {
  FileText,
  FileSpreadsheet,
  Download,
  Printer,
  Share2,
  CheckCircle2,
  AlertTriangle,
  Layers,
  BookOpen,
  ArrowRight,
  Shield,
  FileCheck,
} from 'lucide-react';

export default function ReportsPage() {
  const [activeReportType, setActiveReportType] = useState<'EXECUTIVE' | 'TECHNICAL'>('EXECUTIVE');
  const [pdfGenerating, setPdfGenerating] = useState(false);
  const [notification, setNotification] = useState<string | null>(null);

  const handleDownloadPdf = () => {
    setPdfGenerating(true);
    setTimeout(() => {
      setPdfGenerating(false);
      // Trigger a downloadable file
      const element = document.createElement('a');
      const file = new Blob(
        [
          `IPSEC SENTINEL - ${activeReportType} SECURITY ASSESSMENT DOSSIER\n` +
            `Target: IPSEC-00421 | Date: 2026-09-27 | Authority: NTRO PS-26160\n\n` +
            JSON.stringify(
              activeReportType === 'EXECUTIVE' ? mockExecutiveReport : mockTechnicalReport,
              null,
              2
            ),
        ],
        { type: 'text/plain' }
      );
      element.href = URL.createObjectURL(file);
      element.download = `IPSec_Sentinel_${activeReportType}_Report.txt`;
      document.body.appendChild(element);
      element.click();
      document.body.removeChild(element);
      setNotification(`Generated ${activeReportType} dossier successfully.`);
      setTimeout(() => setNotification(null), 3000);
    }, 900);
  };

  const handleExportJson = () => {
    const reportData = activeReportType === 'EXECUTIVE' ? mockExecutiveReport : mockTechnicalReport;
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
          <div className="flex items-center gap-2">
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
        <div className="panel-technical p-8 rounded-lg max-w-4xl mx-auto shadow-2xl space-y-8 bg-sentinel-deep border border-sentinel-border">
          {activeReportType === 'EXECUTIVE' ? (
            /* EXECUTIVE REPORT DOCUMENT */
            <div className="space-y-6">
              {/* Document Header */}
              <div className="border-b-2 border-sentinel-border pb-5 flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                <div className="space-y-1">
                  <div className="text-[10px] font-mono-tech tracking-widest text-sentinel-copper uppercase font-bold">
                    NATIONAL TECHNICAL RESEARCH ORGANISATION • PS 26160
                  </div>
                  <h2 className="text-lg font-bold text-sentinel-text font-mono-tech">
                    {mockExecutiveReport.title}
                  </h2>
                  <div className="text-xs text-sentinel-muted font-mono-tech">
                    Target Session: {mockExecutiveReport.targetSessionId} • Generated: {mockExecutiveReport.generatedAt}
                  </div>
                </div>
                <div className="p-3 rounded bg-sentinel-secondary border border-sentinel-border text-center font-mono-tech">
                  <div className="text-[10px] text-sentinel-muted uppercase">OVERALL SCORE</div>
                  <div className="text-3xl font-bold text-sentinel-copper">82 / 100</div>
                  <StatusBadge status="MEDIUM" size="sm" />
                </div>
              </div>

              {/* Executive Summary */}
              <div className="space-y-2">
                <h3 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-copper">
                  1. Executive Security Assessment
                </h3>
                <p className="text-xs text-sentinel-text leading-relaxed font-sans">
                  IPsec Sentinel analyzed operational packet captures for border gateway IPSEC-00421. The cryptographic cipher negotiation meets strict sovereign baseline criteria (AES-256-GCM + DH Group 19). However, our deterministic state-machine detected a significant cryptographic vulnerability during Child-SA rekey negotiations, as well as behavioural metadata leakage in unpadded encrypted video streams.
                </p>
              </div>

              {/* Top Findings */}
              <div className="space-y-3">
                <h3 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-copper">
                  2. Key Risk Drivers
                </h3>
                <div className="space-y-2">
                  {mockExecutiveReport.executiveSummary?.topFindings.map((finding, idx) => (
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
                  {mockExecutiveReport.executiveSummary?.businessImpact}
                </div>
              </div>

              {/* Strategic Recommendations */}
              <div className="space-y-2">
                <h3 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-mint">
                  4. Mandated Strategic Recommendations
                </h3>
                <ul className="space-y-2 font-mono-tech text-xs">
                  {mockExecutiveReport.executiveSummary?.highLevelRecommendations.map((rec, idx) => (
                    <li key={idx} className="flex items-start gap-2 text-sentinel-text">
                      <span className="text-sentinel-mint font-bold mt-0.5">✓</span>
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          ) : (
            /* TECHNICAL REPORT DOCUMENT */
            <div className="space-y-6">
              {/* Document Header */}
              <div className="border-b-2 border-sentinel-border pb-5 space-y-1">
                <div className="text-[10px] font-mono-tech tracking-widest text-sentinel-copper uppercase font-bold">
                  TECHNICAL CRYPTOGRAPHIC DOSSIER • PROTOCOL ANALYSIS UNIT
                </div>
                <h2 className="text-lg font-bold text-sentinel-text font-mono-tech">
                  {mockTechnicalReport.title}
                </h2>
                <div className="text-xs text-sentinel-muted font-mono-tech">
                  Investigator: {mockTechnicalReport.author} • Timestamp: {mockTechnicalReport.generatedAt}
                </div>
              </div>

              {/* Session Architecture Details */}
              <div className="space-y-3">
                <h3 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-copper">
                  1. Canonical Session Parameters
                </h3>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono-tech text-xs p-3 bg-sentinel-secondary/30 rounded border border-sentinel-border">
                  <div>
                    <span className="text-[10px] text-sentinel-muted block">SOURCE ENDPOINT</span>
                    <span className="font-bold text-sentinel-text">10.0.1.12</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-sentinel-muted block">DESTINATION GATEWAY</span>
                    <span className="font-bold text-sentinel-text">10.0.2.20</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-sentinel-muted block">INBOUND SPI</span>
                    <span className="font-bold text-sentinel-copper">0x9b4a2e1f</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-sentinel-muted block">OUTBOUND SPI</span>
                    <span className="font-bold text-sentinel-copper">0x3c8d197a</span>
                  </div>
                </div>
              </div>

              {/* Deterministic Evidence Points */}
              <div className="space-y-3">
                <h3 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-copper">
                  2. Forensic Protocol Evidence
                </h3>
                <div className="space-y-2">
                  {mockTechnicalReport.technicalSummary?.groundedEvidencePoints.map((ev, idx) => (
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

              {/* ML Traffic Analysis & Metadata Side-Channel */}
              <div className="space-y-3">
                <h3 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-copper">
                  3. Behavioral Side-Channel Analysis
                </h3>
                <div className="p-3 bg-sentinel-secondary/30 border border-sentinel-border rounded space-y-2 font-mono-tech text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-sentinel-muted">Classifier Result:</span>
                    <span className="text-sentinel-mint font-bold">H.264 Video Streaming (91.4% Confidence)</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sentinel-muted">Temporal Frame Cadence:</span>
                    <span className="text-sentinel-warning font-bold">33.3ms (30 fps Video Pacing)</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sentinel-muted">Traffic Flow Confidentiality:</span>
                    <span className="text-sentinel-critical font-bold">NOT SUPPORTED BY RESPONDER</span>
                  </div>
                </div>
              </div>

              {/* Compliance Scorecard */}
              <div className="space-y-2">
                <h3 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-copper">
                  4. RFC Compliance Verification Statistics
                </h3>
                <div className="grid grid-cols-4 gap-3 text-center font-mono-tech text-xs">
                  <div className="p-2.5 bg-sentinel-secondary/40 rounded border border-sentinel-border">
                    <div className="text-[10px] text-sentinel-muted">TOTAL RULES</div>
                    <div className="text-lg font-bold text-sentinel-text">24</div>
                  </div>
                  <div className="p-2.5 bg-sentinel-secondary/40 rounded border border-sentinel-border">
                    <div className="text-[10px] text-sentinel-muted">PASSED</div>
                    <div className="text-lg font-bold text-sentinel-mint">18</div>
                  </div>
                  <div className="p-2.5 bg-sentinel-secondary/40 rounded border border-sentinel-border">
                    <div className="text-[10px] text-sentinel-muted">WARNINGS</div>
                    <div className="text-lg font-bold text-sentinel-warning">4</div>
                  </div>
                  <div className="p-2.5 bg-sentinel-secondary/40 rounded border border-sentinel-border">
                    <div className="text-[10px] text-sentinel-muted">FAILED</div>
                    <div className="text-lg font-bold text-sentinel-critical">2</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Document Footer Signoff */}
          <div className="pt-6 border-t border-sentinel-border flex items-center justify-between font-mono-tech text-[10px] text-sentinel-muted">
            <span>SOVEREIGN CLASSIFICATION: CONFIDENTIAL / NTRO-SIH-26160</span>
            <span>DIGITALLY SIGNED VIA ECDSA-P256</span>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
