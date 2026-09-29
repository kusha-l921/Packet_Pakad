'use client';

import React, { useState, useEffect } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import { AnalysisTabs } from '@/components/analysis/AnalysisTabs';
import { fetchCryptoPosture } from '@/lib/api/analysis';
import { fetchTestbedStatus } from '@/lib/api/testbed';
import { ProgressBar } from '@/components/common/TechnicalField';
import { NoDataState } from '@/components/common/NoDataState';
import { SessionSelector } from '@/components/common/SessionSelector';
import { useSession } from '@/context/SessionContext';
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
  const { selectedSessionId, selectedSession, sessions } = useSession();
  const [cryptoData, setCryptoData] = useState<{ vectors: any[]; similarity: any }>({
    vectors: [],
    similarity: { bestMatch: '', profiles: [] },
  });
  const [testbedStatus, setTestbedStatus] = useState<any>(null);

  const currentSession =
    selectedSession ||
    sessions.find(
      (s) =>
        s.id.toLowerCase() === (selectedSessionId || '').toLowerCase() ||
        s.rawId?.toLowerCase() === (selectedSessionId || '').toLowerCase()
    ) ||
    sessions[0];

  useEffect(() => {
    fetchTestbedStatus()
      .then(setTestbedStatus)
      .catch(() => {});

    fetchCryptoPosture(selectedSessionId || currentSession?.id || undefined)
      .then((data) => {
        if (data && data.vectors && data.vectors.length > 0) {
          setCryptoData(data as any);
        } else {
          setCryptoData({ vectors: [], similarity: { bestMatch: '', profiles: [] } });
        }
      })
      .catch(() => {});
  }, [selectedSessionId, currentSession?.id]);

  const hasData = Boolean(
    cryptoData &&
    Array.isArray(cryptoData.vectors) &&
    cryptoData.vectors.length > 0
  );

  const cipherDisplay =
    currentSession?.cipher ||
    currentSession?.encryption ||
    cryptoData.vectors.find((v) => v.dimension?.toLowerCase().includes('cipher'))?.value ||
    'AES-256-GCM';

  const integDisplay = currentSession?.crypto?.integrity
    ? `${currentSession.crypto.integrity} / ${currentSession.crypto.prf}`
    : currentSession?.integrity ||
      cryptoData.vectors.find((v) => v.dimension?.toLowerCase().includes('integrity'))?.value ||
      'SHA-256 / PRF';

  const keDisplay =
    currentSession?.crypto?.dhGroup ||
    (currentSession?.dhGroup ? `DH GROUP ${currentSession.dhGroup}` : null) ||
    cryptoData.vectors.find((v) => v.dimension?.toLowerCase().includes('key exchange'))?.value ||
    'Curve25519 (X25519)';

  const pfsActive = Boolean(
    currentSession?.pfs ??
    (cryptoData.vectors.find((v) => v.dimension?.toLowerCase().includes('forward secrecy'))?.value === 'Enabled')
  );

  return (
    <AppShell>
      <div className="space-y-6 max-w-7xl mx-auto">
        {/* Navigation Tabs for Analysis Section */}
        <AnalysisTabs />

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

          <div className="flex items-center gap-2 flex-wrap">
            <SessionSelector />
          </div>
        </div>

        {!hasData ? (
          <NoDataState
            title="NO DATA TO PROCESS"
            description="No active IPsec session or cryptographic vector evaluation is currently running. Deploy the testbed to compute 19-dimensional vector alignment and compare against sovereign standards."
          />
        ) : (
          <>
            {/* Observed Configuration Strip */}
            <div className="panel-technical p-4 rounded-lg space-y-2 border-l-4 border-l-sentinel-copper">
              <div className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                OBSERVED CRYPTOGRAPHIC CONFIGURATION {currentSession ? `[${currentSession.id}]` : (selectedSessionId ? `[${selectedSessionId}]` : '')}
              </div>
              <div className="flex flex-wrap items-center gap-3 font-mono-tech text-xs">
                <div className="px-2.5 py-1 rounded bg-sentinel-secondary border border-sentinel-border text-sentinel-text">
                  CIPHER: <span className="text-sentinel-copper font-bold">{cipherDisplay}</span>
                </div>
                <div className="px-2.5 py-1 rounded bg-sentinel-secondary border border-sentinel-border text-sentinel-text">
                  INTEGRITY / PRF: <span className="text-sentinel-copper font-bold">{integDisplay}</span>
                </div>
                <div className="px-2.5 py-1 rounded bg-sentinel-secondary border border-sentinel-border text-sentinel-text">
                  KEY EXCHANGE: <span className="text-sentinel-copper font-bold">{keDisplay}</span>
                </div>
                <div className={`px-2.5 py-1 rounded border font-bold ${
                  pfsActive
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-800 dark:text-sentinel-mint'
                    : 'bg-amber-500/15 border-amber-500/30 text-amber-800 dark:text-sentinel-warning'
                }`}>
                  PFS: {pfsActive ? 'ENABLED (CHILD SA DERIVED)' : 'DISABLED (NO CHILD DH)'}
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
            {(() => {
              const profiles = cryptoData.similarity?.profiles || [];
              const highestScore = Math.max(...profiles.map((p: any) => p.matchPercentage || 0), 0);

              return profiles.map((prof: any) => {
                const isHighest = prof.matchPercentage === highestScore && highestScore > 0;
                const isPqcOrCnsa = prof.name?.includes('CNSA') || prof.name?.includes('PQC');
                const isRfcBaseline = (prof.name?.includes('Classical') || prof.name?.includes('Baseline')) && !prof.name?.includes('Prohibited');
                const isProhibitedOrDeprecated = prof.name?.includes('Prohibited') || prof.name?.includes('Deprecated') || prof.name?.includes('131A');

                let cardStyle = 'bg-sentinel-secondary/30 border-sentinel-border';
                let statusColor = 'text-sentinel-muted';
                let matchColor = 'text-sentinel-text';
                let titleColor = 'text-sentinel-text';
                let descColor = 'text-sentinel-muted';
                let barColor: 'mint' | 'copper' | 'warning' | 'critical' = prof.matchPercentage > 80 ? 'copper' : prof.matchPercentage > 40 ? 'mint' : 'warning';
                let bestBadge = '';

                if (isHighest) {
                  if (isPqcOrCnsa) {
                    cardStyle = 'bg-emerald-50 border-emerald-500 shadow-md shadow-emerald-500/15 ring-2 ring-emerald-500/80 dark:bg-emerald-950/30 dark:border-emerald-500/80 dark:shadow-[0_0_22px_rgba(16,185,129,0.35)] dark:ring-1 dark:ring-emerald-500/50';
                    statusColor = 'text-emerald-700 dark:text-emerald-400 font-bold';
                    matchColor = 'text-emerald-800 dark:text-emerald-300 font-bold';
                    titleColor = 'text-emerald-950 dark:text-emerald-200 font-bold';
                    descColor = 'text-emerald-900/80 dark:text-emerald-100/70 font-medium';
                    barColor = 'mint';
                    bestBadge = 'bg-emerald-600 text-white dark:bg-emerald-500/20 dark:text-emerald-300 dark:border dark:border-emerald-500/40';
                  } else if (isRfcBaseline) {
                    cardStyle = 'bg-sky-50 border-sky-500 shadow-md shadow-sky-500/15 ring-2 ring-sky-500/80 dark:bg-sky-950/30 dark:border-sky-500/80 dark:shadow-[0_0_22px_rgba(14,165,233,0.35)] dark:ring-1 dark:ring-sky-500/50';
                    statusColor = 'text-sky-700 dark:text-sky-400 font-bold';
                    matchColor = 'text-sky-800 dark:text-sky-300 font-bold';
                    titleColor = 'text-sky-950 dark:text-sky-200 font-bold';
                    descColor = 'text-sky-900/80 dark:text-sky-100/70 font-medium';
                    barColor = 'copper';
                    bestBadge = 'bg-sky-600 text-white dark:bg-sky-500/20 dark:text-sky-300 dark:border dark:border-sky-500/40';
                  } else if (isProhibitedOrDeprecated) {
                    cardStyle = 'bg-rose-50 border-rose-500 shadow-md shadow-rose-500/15 ring-2 ring-rose-500/80 dark:bg-red-950/30 dark:border-red-500/80 dark:shadow-[0_0_22px_rgba(239,68,68,0.35)] dark:ring-1 dark:ring-red-500/50';
                    statusColor = 'text-rose-700 dark:text-red-400 font-bold';
                    matchColor = 'text-rose-800 dark:text-red-300 font-bold';
                    titleColor = 'text-rose-950 dark:text-red-200 font-bold';
                    descColor = 'text-rose-900/80 dark:text-rose-100/70 font-medium';
                    barColor = 'critical';
                    bestBadge = 'bg-rose-600 text-white dark:bg-red-500/20 dark:text-red-300 dark:border dark:border-red-500/40';
                  } else {
                    cardStyle = 'bg-orange-50 border-orange-500 shadow-md shadow-orange-500/10 ring-2 ring-orange-500/80 dark:bg-orange-950/30 dark:border-orange-500/80 dark:shadow-[0_0_22px_rgba(255,107,0,0.35)] dark:ring-1 dark:ring-orange-500/50';
                    statusColor = 'text-orange-700 dark:text-orange-400 font-bold';
                    matchColor = 'text-orange-800 dark:text-orange-300 font-bold';
                    titleColor = 'text-orange-950 dark:text-white font-bold';
                    descColor = 'text-orange-900/80 dark:text-orange-100/70 font-medium';
                    barColor = 'copper';
                    bestBadge = 'bg-orange-500 text-white dark:bg-orange-500/20 dark:text-orange-300 dark:border dark:border-orange-500/40';
                  }
                }

                return (
                  <div
                    key={prof.name}
                    className={`p-4 rounded-lg border space-y-3 flex flex-col justify-between transition-all duration-300 ${cardStyle}`}
                  >
                    <div>
                      <div className="flex items-center justify-between text-[10px] font-mono-tech gap-2">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className={`uppercase tracking-wider ${statusColor}`}>
                            {prof.status}
                          </span>
                          {isHighest && bestBadge && (
                            <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider shadow-xs ${bestBadge}`}>
                              BEST MATCH
                            </span>
                          )}
                        </div>
                        <span className={`font-mono-tech ${matchColor}`}>
                          {prof.matchPercentage}% MATCH
                        </span>
                      </div>
                      <div className={`font-mono-tech text-sm mt-1.5 ${titleColor}`}>
                        {prof.name}
                      </div>
                      <p className={`text-xs mt-2 leading-relaxed ${descColor}`}>
                        {prof.description}
                      </p>
                    </div>

                    <div className="space-y-1 pt-2">
                      <ProgressBar
                        value={prof.matchPercentage}
                        max={100}
                        color={barColor}
                        height="h-1.5"
                      />
                      <div className={`text-[10px] font-mono-tech text-right ${isHighest ? 'font-semibold text-sentinel-text' : 'text-sentinel-muted'}`}>
                        Euclidean Distance: {((100 - prof.matchPercentage) / 100).toFixed(2)}
                      </div>
                    </div>
                  </div>
                );
              });
            })()}
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
                {cryptoData.vectors.map((item, i) => (
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
                        <span className="text-emerald-700 dark:text-sentinel-mint font-medium flex items-center gap-1 text-[11px]">
                          <CheckCircle2 className="w-3 h-3 text-emerald-600 dark:text-sentinel-mint" /> Resistant (Grover)
                        </span>
                      ) : (
                        <span className="text-amber-800 dark:text-sentinel-warning font-medium flex items-center gap-1 text-[11px]">
                          <AlertTriangle className="w-3 h-3 text-amber-600 dark:text-sentinel-warning" /> Vulnerable (Shor)
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
        </>
      )}
    </div>
  </AppShell>
);
}
