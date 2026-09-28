'use client';

import React from 'react';
import { Database, Download, FileSpreadsheet, HardDrive, CheckCircle2 } from 'lucide-react';

export default function DatasetPage() {
  const datasets = [
    { name: 'ntro_benchmark_ikev2_normal.pcap', size: '48.2 MB', sessions: 120, label: 'BENCHMARK CLEAN', date: '2026-09-20' },
    { name: 'ntro_pfs_degraded_rekey.pcap', size: '18.4 MB', sessions: 24, label: 'RFC-C-027 VIOLATION', date: '2026-09-22' },
    { name: 'synthetic_video_rtp_30hz_cadence.pcap', size: '124.6 MB', sessions: 8, label: 'SIDE-CHANNEL METADATA', date: '2026-09-25' },
    { name: 'deprecated_3des_sha1_handshake.pcap', size: '4.1 MB', sessions: 2, label: 'CRITICAL VULN', date: '2026-09-26' },
  ];

  return (
    <div className="space-y-6 font-mono text-xs">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-sentinel-border">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Database className="w-4 h-4 text-sentinel-copper" />
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-sentinel-text uppercase">
              GROUND TRUTH DATASET REPOSITORY
            </h1>
          </div>
          <p className="text-xs text-sentinel-text-muted">
            Curated PCAP sample corpus with cryptographic ground truth labels for benchmarking model accuracy.
          </p>
        </div>

        <button className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-sentinel-copper bg-sentinel-copper text-white dark:text-[#0B0C0D] font-bold hover:bg-sentinel-copper/90 transition-colors">
          <span>+ Ingest Custom PCAP</span>
        </button>
      </div>

      <div className="rounded-xl border border-sentinel-border bg-[#101214] divide-y divide-sentinel-border/60">
        {datasets.map((ds, idx) => (
          <div key={idx} className="p-4 flex items-center justify-between hover:bg-[#151719] transition-colors">
            <div className="flex items-center gap-3">
              <HardDrive className="w-4 h-4 text-sentinel-copper" />
              <div>
                <div className="font-bold text-sentinel-text">{ds.name}</div>
                <div className="text-[10px] text-sentinel-text-muted">
                  Size: {ds.size} • Sessions: {ds.sessions} • Captured: {ds.date}
                </div>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <span className="text-[10px] px-2 py-0.5 rounded font-bold border border-sentinel-border bg-[#0B0C0D] text-sentinel-copper">
                {ds.label}
              </span>
              <button className="p-1.5 rounded border border-sentinel-border hover:border-sentinel-copper text-sentinel-text-muted hover:text-sentinel-text">
                <Download className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
