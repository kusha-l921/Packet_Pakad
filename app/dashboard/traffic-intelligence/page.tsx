'use client';

import React from 'react';
import { Binary, Activity, AlertTriangle, CheckCircle2, TrendingUp, Cpu } from 'lucide-react';

export default function TrafficIntelligencePage() {
  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-sentinel-border">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Binary className="w-4 h-4 text-sentinel-copper" />
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-sentinel-text uppercase">
              AI / ML ENCRYPTED TRAFFIC INTELLIGENCE
            </h1>
          </div>
          <p className="text-xs text-sentinel-text-muted">
            Passive side-channel inference: packet length distributions, inter-arrival timing cadences, and entropy profiling.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-sentinel-copper font-bold px-2.5 py-1 rounded border border-sentinel-copper/30 bg-sentinel-copper/10">
            MODEL: XGBOOST-CNN ENSEMBLE (94.2% CONFIDENCE)
          </span>
        </div>
      </div>

      {/* 2 Column Stats & Cadence Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Inferred Traffic Classification */}
        <div className="lg:col-span-7 p-6 rounded-xl border border-sentinel-border bg-[#101214] space-y-5">
          <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
            <span className="text-xs font-bold uppercase tracking-wider text-sentinel-text">
              ENCRYPTED PROTOCOL INFERENCE (SESSION IPSEC-00421)
            </span>
            <span className="text-[10px] text-sentinel-mint">LIVE STREAM</span>
          </div>

          <div className="space-y-3">
            <div>
              <div className="flex justify-between mb-1 text-xs">
                <span className="text-sentinel-text font-bold">H.264 / RTP Video Streaming</span>
                <span className="text-sentinel-copper font-bold">94.2%</span>
              </div>
              <div className="w-full h-2 bg-sentinel-border rounded overflow-hidden">
                <div className="h-full bg-sentinel-copper w-[94.2%]" />
              </div>
            </div>

            <div>
              <div className="flex justify-between mb-1 text-xs">
                <span className="text-sentinel-text-muted">HTTPS / TLS 1.3 Bulk Web</span>
                <span className="text-sentinel-text-muted">4.1%</span>
              </div>
              <div className="w-full h-1.5 bg-sentinel-border rounded overflow-hidden">
                <div className="h-full bg-sentinel-border/80 w-[4.1%]" />
              </div>
            </div>

            <div>
              <div className="flex justify-between mb-1 text-xs">
                <span className="text-sentinel-text-muted">SSH / Interactive Terminal</span>
                <span className="text-sentinel-text-muted">1.2%</span>
              </div>
              <div className="w-full h-1.5 bg-sentinel-border rounded overflow-hidden">
                <div className="h-full bg-sentinel-border/80 w-[1.2%]" />
              </div>
            </div>
          </div>

          <div className="p-4 rounded-lg border border-sentinel-border bg-[#151719] space-y-2 text-[11px]">
            <div className="text-sentinel-copper font-bold uppercase text-[10px]">
              EVIDENCE CORRELATION
            </div>
            <div className="text-sentinel-text-muted leading-relaxed">
              Burst cadence analysis reveals packet clusters spaced at 33.3ms intervals, precisely matching 30 fps video frame downlink. Standard deviation of packet sizes exhibits bimodal peaks at 1420 bytes (I/P-frames) and 180 bytes (RTCP feedback).
            </div>
          </div>
        </div>

        {/* Right: Metadata Leakage & Side-Channel Warning */}
        <div className="lg:col-span-5 p-6 rounded-xl border border-sentinel-border bg-[#101214] flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center gap-2 pb-3 mb-3 border-b border-sentinel-border text-sentinel-warning">
              <AlertTriangle className="w-4 h-4" />
              <span className="font-bold text-xs uppercase tracking-wider text-sentinel-text">
                METADATA LEAKAGE WARNING
              </span>
            </div>

            <div className="text-xs text-sentinel-text leading-relaxed mb-4">
              <strong>TFC Padding Missing:</strong> The IPsec tunnel is not utilizing Traffic Flow Confidentiality (RFC 4303 §2.7). As a consequence, third-party wiretaps can infer user activity types solely by observing outer ESP packet lengths.
            </div>

            <div className="p-3 rounded border border-sentinel-border bg-[#0B0C0D] text-[10px] space-y-1 text-sentinel-text-muted">
              <div>Detected Cadence: <strong className="text-sentinel-text">30.0 Hz (Video Downlink)</strong></div>
              <div>Bitrate Variance: <strong className="text-sentinel-text">1.2 Mbps VBR</strong></div>
              <div>Mitigation: <strong className="text-sentinel-mint">Enable TFC dummy padding</strong></div>
            </div>
          </div>

          <div className="pt-3 border-t border-sentinel-border text-[11px] text-sentinel-copper">
            Rule Triggered: META-D14 (Side-Channel Fingerprint)
          </div>
        </div>
      </div>
    </div>
  );
}
