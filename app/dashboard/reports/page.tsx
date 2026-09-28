'use client';

import React from 'react';
import { FileSpreadsheet, Download, Printer, CheckCircle2, Shield, Copy } from 'lucide-react';

export default function ReportsPage() {
  return (
    <div className="space-y-6 font-mono text-xs">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-sentinel-border">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <FileSpreadsheet className="w-4 h-4 text-sentinel-copper" />
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-sentinel-text uppercase">
              EXECUTIVE & TECHNICAL AUDIT REPORTS
            </h1>
          </div>
          <p className="text-xs text-sentinel-text-muted">
            RAG-synthesized cryptographic compliance reports grounded strictly in deterministic packet evidence.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-sentinel-border bg-[#151719] text-sentinel-text hover:border-sentinel-copper transition-colors">
            <Printer className="w-3.5 h-3.5" />
            <span>Print PDF</span>
          </button>
          <button className="flex items-center gap-1.5 px-3.5 py-1.5 rounded border border-sentinel-copper bg-sentinel-copper text-white dark:text-[#0B0C0D] font-bold hover:bg-sentinel-copper/90 transition-colors">
            <Download className="w-3.5 h-3.5" />
            <span>Export Official Dossier</span>
          </button>
        </div>
      </div>

      {/* Official Audit Document Sheet Preview */}
      <div className="p-8 rounded-xl border border-sentinel-border bg-[#101214] max-w-4xl mx-auto space-y-6 shadow-2xl">
        <div className="flex items-center justify-between pb-4 border-b border-sentinel-border">
          <div>
            <div className="text-xs text-sentinel-copper font-bold uppercase tracking-wider">
              NATIONAL TECHNICAL RESEARCH ORGANISATION (NTRO)
            </div>
            <div className="text-base font-bold text-sentinel-text mt-1">
              CRYPTOGRAPHIC VULNERABILITY ASSESSMENT REPORT #26160-C3
            </div>
          </div>
          <div className="text-right text-[10px] text-sentinel-text-muted">
            <div>DATE: 2026-09-27</div>
            <div className="text-sentinel-critical font-bold">CLASSIFICATION: SECRET</div>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 p-4 rounded-lg border border-sentinel-border bg-[#0B0C0D]">
          <div>
            <div className="text-sentinel-text-muted text-[10px]">EVALUATED GATEWAY</div>
            <div className="font-bold text-sentinel-text mt-0.5">GW-DEL-BORDER-01</div>
          </div>
          <div>
            <div className="text-sentinel-text-muted text-[10px]">SECURITY SCORE</div>
            <div className="font-bold text-sentinel-copper mt-0.5">82 / 100 (MEDIUM)</div>
          </div>
          <div>
            <div className="text-sentinel-text-muted text-[10px]">RFC COMPLIANCE</div>
            <div className="font-bold text-sentinel-mint mt-0.5">87% PASSED</div>
          </div>
          <div>
            <div className="text-sentinel-text-muted text-[10px]">VERIFIED FRAMES</div>
            <div className="font-bold text-sentinel-text mt-0.5">65,421 PKTS</div>
          </div>
        </div>

        <div>
          <h2 className="text-xs font-bold text-sentinel-text uppercase mb-2">1. EXECUTIVE SUMMARY</h2>
          <p className="text-xs text-sentinel-text-muted font-sans leading-relaxed">
            The monitored border gateway establishes robust classical confidentiality utilizing AES-256-GCM authenticated encryption and Diffie-Hellman Group 19. However, the operational baseline reveals two critical posture degradations: Child SA rekeys fail to enforce Perfect Forward Secrecy due to missing KE payloads, and absence of Traffic Flow Confidentiality (TFC) allows passive wiretappers to fingerprint internal video streams.
          </p>
        </div>

        <div>
          <h2 className="text-xs font-bold text-sentinel-text uppercase mb-2">2. REMEDIATION CONFIGURATION DIFF (SWANCTL.CONF)</h2>
          <div className="p-3.5 rounded border border-sentinel-border bg-[#0B0C0D] text-[11px] text-sentinel-text">
            <pre className="font-mono text-sentinel-text-muted">
{`connections {
    gw-del-hq {
-       esp_proposals = aes256gcm16
+       esp_proposals = aes256gcm16-modp2048!
-       rekey_time = 86400s
+       rekey_time = 7200s
+       tfc_padding = yes
    }
}`}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
