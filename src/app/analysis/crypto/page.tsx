'use client';

import React from 'react';
import { AppShell } from '@/components/layout/AppShell';
import { mockCryptoVectorData, mockProfileSimilarity } from '@/data/crypto';
import { ProgressBar } from '@/components/common/TechnicalField';
import { motion } from 'framer-motion';
import {
  Binary,
  Key,
  Shield,
  Layers,
  Sparkles,
  Info,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';

export default function CryptoPosturePage() {
  return (
    <AppShell>
      <div className="space-y-6 max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-sentinel-border">
          <div>
            <div className="flex items-center gap-2">
              <Binary className="w-5 h-5 text-sentinel-copper" />
              <h1 className="font-mono-tech text-base md:text-lg font-bold tracking-wider text-sentinel-text uppercase">
                Cryptographic Vector Analysis & Posture
              </h1>
            </div>
            <p className="text-xs text-sentinel-muted mt-0.5">
              Normalized cryptographic bit-strength evaluation and mathematical profile similarity matching.
            </p>
          </div>

          <div className="flex items-center gap-2 font-mono-tech text-xs">
            <span className="text-sentinel-muted">TARGET:</span>
            <span className="px-2 py-0.5 rounded bg-sentinel-secondary border border-sentinel-border text-sentinel-copper font-bold">
              IPSEC-00421
            </span>
          </div>
        </div>

        {/* Observed Configuration Strip */}
        <div className="panel-technical p-4 rounded-lg space-y-2 border-l-4 border-l-sentinel-copper">
          <div className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
            OBSERVED CRYPTOGRAPHIC CONFIGURATION
          </div>
          <div className="flex flex-wrap items-center gap-3 font-mono-tech text-xs">
            <div className="px-2.5 py-1 rounded bg-sentinel-secondary border border-sentinel-border text-sentinel-text">
              CIPHER: <span className="text-sentinel-copper font-bold">AES-256-GCM</span>
            </div>
            <div className="px-2.5 py-1 rounded bg-sentinel-secondary border border-sentinel-border text-sentinel-text">
              INTEGRITY / PRF: <span className="text-sentinel-copper font-bold">SHA-256</span>
            </div>
            <div className="px-2.5 py-1 rounded bg-sentinel-secondary border border-sentinel-border text-sentinel-text">
              KEY EXCHANGE: <span className="text-sentinel-copper font-bold">DH GROUP 19 (P-256)</span>
            </div>
            <div className="px-2.5 py-1 rounded bg-sentinel-mint/15 border border-sentinel-mint/30 text-sentinel-mint font-bold">
              PFS: ENABLED (CHILD SA DERIVED)
            </div>
          </div>
        </div>

        {/* PROFILE SIMILARITY ANALYSIS (Explicitly non-arbitrary mathematical similarity) */}
        <div className="panel-technical p-5 rounded-lg space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-sentinel-border">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-sentinel-copper" />
              <h2 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                PROFILE SIMILARITY ANALYSIS
              </h2>
            </div>
            <div className="flex items-center gap-1.5 text-[10px] font-mono-tech text-sentinel-muted bg-sentinel-secondary px-2 py-0.5 rounded border border-sentinel-border">
              <Info className="w-3 h-3 text-sentinel-copper" />
              <span>Cosine Vector Distance against Cryptographic Suites (Non-arbitrary)</span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {mockProfileSimilarity.profiles.map((prof) => (
              <div
                key={prof.name}
                className="p-4 rounded-lg bg-sentinel-secondary/30 border border-sentinel-border space-y-3 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between text-[10px] font-mono-tech">
                    <span className="text-sentinel-muted uppercase">{prof.status}</span>
                    <span className="text-sentinel-text font-bold">{prof.matchPercentage}% MATCH</span>
                  </div>
                  <div className="font-mono-tech text-sm font-bold text-sentinel-text mt-1">
                    {prof.name}
                  </div>
                  <p className="text-xs text-sentinel-muted mt-2 leading-relaxed">
                    {prof.description}
                  </p>
                </div>

                <div className="space-y-1 pt-2">
                  <ProgressBar
                    value={prof.matchPercentage}
                    max={100}
                    color={
                      prof.matchPercentage > 80
                        ? 'copper'
                        : prof.matchPercentage > 40
                        ? 'mint'
                        : 'warning'
                    }
                    height="h-1.5"
                  />
                  <div className="text-[10px] font-mono-tech text-right text-sentinel-muted">
                    Euclidean Distance: {((100 - prof.matchPercentage) / 100).toFixed(2)}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Normalized Crypto Vector Visualization Table */}
        <div className="panel-technical rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
            <div className="flex items-center gap-2">
              <Key className="w-4 h-4 text-sentinel-copper" />
              <h2 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                Normalized Cryptographic Parameter Vectors
              </h2>
            </div>
            <span className="text-[10px] font-mono-tech text-sentinel-muted">
              NIST SP 800-57 / CNSA 1.0 Assessment
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono-tech text-xs border-collapse">
              <thead className="bg-sentinel-secondary/60 text-sentinel-muted text-[10px] uppercase border-b border-sentinel-border">
                <tr>
                  <th className="py-2.5 px-3">Cryptographic Vector</th>
                  <th className="py-2.5 px-3">Observed Parameter</th>
                  <th className="py-2.5 px-3">Security Bits</th>
                  <th className="py-2.5 px-3">Post-Quantum Status</th>
                  <th className="py-2.5 px-3">Normalized Score</th>
                  <th className="py-2.5 px-3">Standard Reference</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sentinel-border">
                {mockCryptoVectorData.map((item, i) => (
                  <tr key={i} className="hover:bg-sentinel-elevated transition-colors">
                    <td className="py-3 px-3 font-semibold text-sentinel-text">
                      {item.parameter}
                    </td>
                    <td className="py-3 px-3 text-sentinel-copper font-medium">
                      {item.observedValue}
                    </td>
                    <td className="py-3 px-3 text-sentinel-text">
                      {item.securityBits} bits
                    </td>
                    <td className="py-3 px-3">
                      {item.quantumResistant ? (
                        <span className="text-sentinel-mint flex items-center gap-1 text-[11px]">
                          <CheckCircle2 className="w-3 h-3" /> Resistant (Grover)
                        </span>
                      ) : (
                        <span className="text-sentinel-warning flex items-center gap-1 text-[11px]">
                          <AlertTriangle className="w-3 h-3" /> Vulnerable (Shor)
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-3 w-40">
                      <div className="flex items-center gap-2">
                        <ProgressBar
                          value={item.normalizedScore}
                          max={100}
                          color={item.normalizedScore >= 90 ? 'mint' : 'copper'}
                          height="h-1.5"
                        />
                        <span className="text-[11px] text-sentinel-text">
                          {item.normalizedScore}
                        </span>
                      </div>
                    </td>
                    <td className="py-3 px-3 text-sentinel-muted text-[11px]">
                      {item.standardCompliance}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
