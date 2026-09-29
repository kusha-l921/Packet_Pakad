'use client';

import React, { useState, useEffect } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import { fetchThreatFindings } from '@/lib/api/analysis';
import { fetchTestbedStatus } from '@/lib/api/testbed';
import { StatusBadge } from '@/components/common/StatusBadge';
import { NoDataState } from '@/components/common/NoDataState';
import { SessionSelector } from '@/components/common/SessionSelector';
import { useSession } from '@/context/SessionContext';
import { ThreatFinding } from '@/types';
import { motion, AnimatePresence } from 'framer-motion';
import {
  AlertOctagon,
  ShieldAlert,
  ChevronDown,
  ChevronRight,
  Filter,
  Layers,
  ArrowRight,
  Info,
  ExternalLink,
} from 'lucide-react';
import Link from 'next/link';

import { mockThreatFindings } from '@/data/findings';

export default function ThreatMatrixPage() {
  const { selectedSessionId, selectedSession } = useSession();
  const [threats, setThreats] = useState<ThreatFinding[]>(mockThreatFindings);
  const [selectedFinding, setSelectedFinding] = useState<ThreatFinding | null>(mockThreatFindings[0]);
  const [expandedFeedId, setExpandedFeedId] = useState<string | null>(mockThreatFindings[0].id);
  const [testbedStatus, setTestbedStatus] = useState<any>(null);

  useEffect(() => {
    fetchTestbedStatus()
      .then(setTestbedStatus)
      .catch(() => {});

    fetchThreatFindings(selectedSessionId || undefined)
      .then((t) => {
        const list = (t && t.length > 0) ? t : mockThreatFindings;
        setThreats(list);
        setSelectedFinding(list[0]);
        setExpandedFeedId(list[0].id);
      })
      .catch(() => {
        setThreats(mockThreatFindings);
        setSelectedFinding(mockThreatFindings[0]);
        setExpandedFeedId(mockThreatFindings[0].id);
      });
  }, [selectedSessionId]);

  const hasData = Boolean(
    Array.isArray(threats) && threats.length > 0
  );

  const toggleFeed = (id: string) => {
    setExpandedFeedId(expandedFeedId === id ? null : id);
  };

  const getSeverityBadgeColor = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-rose-600 text-white border border-rose-700 shadow-xs hover:bg-rose-700';
      case 'HIGH':
        return 'bg-rose-500 text-white border border-rose-600 shadow-xs hover:bg-rose-600';
      case 'MEDIUM':
        return 'bg-amber-500 text-slate-950 font-extrabold border border-amber-600 shadow-xs hover:bg-amber-600';
      case 'LOW':
      default:
        return 'bg-emerald-600 text-white border border-emerald-700 shadow-xs hover:bg-emerald-700';
    }
  };

  return (
    <AppShell>
      <div className="space-y-6 max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-sentinel-border">
          <div>
            <div className="flex items-center gap-2">
              <AlertOctagon className="w-5 h-5 text-sentinel-copper" />
              <h1 className="font-mono-tech text-base md:text-lg font-bold tracking-wider text-sentinel-text uppercase">
                Threat Matrix & Security Findings
              </h1>
            </div>
            <p className="text-xs text-sentinel-muted mt-0.5">
              Multi-dimensional threat modeling correlating deterministic rule violations, cryptographic regressions, and ML side-channel risks.
            </p>
          </div>

          <div className="flex items-center gap-3 flex-wrap">
            <SessionSelector />
            <div className="flex items-center gap-2 font-mono-tech text-xs">
              <span className="text-sentinel-muted">FINDINGS:</span>
              <span className="px-2 py-0.5 rounded bg-sentinel-critical/20 border border-sentinel-critical/40 text-sentinel-critical font-bold">
                {threats.length}
              </span>
            </div>
          </div>
        </div>

        {!hasData ? (
          <NoDataState
            title="NO THREAT DATA TO PROCESS"
            description="No active IPsec session or threat anomalies currently detected. Deploy the testbed to inspect protocol exchanges for threat vectors."
          />
        ) : (
          <>
            {/* 2-Column Workstation: LEFT Interactive Matrix & RIGHT Finding Details */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Interactive Threat Risk Matrix (7 Cols) */}
          <div className="lg:col-span-7 panel-technical p-5 rounded-lg space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-sentinel-border">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-sentinel-copper" />
                <h2 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                  Interactive Likelihood vs Impact Risk Matrix
                </h2>
              </div>
              <span className="text-[10px] font-mono-tech text-sentinel-muted">
                X: Likelihood (1-5) • Y: Impact (1-5)
              </span>
            </div>

            {/* Matrix Grid Visualization - Dark Themed Cyber Aesthetic */}
            <div className="relative p-6 bg-[#080a0f] border border-slate-800/90 rounded-xl select-none shadow-2xl overflow-hidden">
              {/* Subtle cyber grid background effect */}
              <div 
                className="absolute inset-0 pointer-events-none opacity-25"
                style={{
                  backgroundImage: `radial-gradient(circle at 50% 50%, rgba(56, 189, 248, 0.08) 0%, transparent 70%), linear-gradient(rgba(255, 255, 255, 0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(255, 255, 255, 0.04) 1px, transparent 1px)`,
                  backgroundSize: '100% 100%, 28px 28px, 28px 28px'
                }}
              />
              
              {/* Corner tech accents */}
              <div className="absolute top-2 left-2 w-2 h-2 border-t-2 border-l-2 border-sentinel-copper/60 pointer-events-none" />
              <div className="absolute top-2 right-2 w-2 h-2 border-t-2 border-r-2 border-sentinel-copper/60 pointer-events-none" />
              <div className="absolute bottom-2 left-2 w-2 h-2 border-b-2 border-l-2 border-sentinel-copper/60 pointer-events-none" />
              <div className="absolute bottom-2 right-2 w-2 h-2 border-b-2 border-r-2 border-sentinel-copper/60 pointer-events-none" />

              {/* Y-Axis Label */}
              <div className="absolute left-1 top-1/2 -translate-y-1/2 -rotate-90 text-[10px] font-mono-tech uppercase tracking-widest text-slate-400 font-semibold z-10 flex items-center gap-1.5">
                <span>←</span>
                <span>IMPACT</span>
                <span>→</span>
              </div>

              {/* Matrix Cell Grid (5x5) */}
              <div className="grid grid-rows-5 gap-1.5 ml-8 mb-4 relative z-10">
                {[5, 4, 3, 2, 1].map((impactVal) => (
                  <div key={impactVal} className="grid grid-cols-5 gap-1.5 h-14 relative">
                    {/* Y-Axis Level Tick Number */}
                    <div className="absolute -left-5 top-1/2 -translate-y-1/2 text-[10px] font-mono-tech font-bold text-slate-500">
                      {impactVal}
                    </div>

                    {[1, 2, 3, 4, 5].map((likelihoodVal) => {
                      const findingsInCell = threats.filter(
                        (f) => f.likelihood === likelihoodVal && f.impact === impactVal
                      );

                      const score = impactVal * likelihoodVal;
                      const isCriticalZone = score >= 15;
                      const isHighZone = score >= 10 && score < 15;
                      const isMedZone = score >= 5 && score < 10;

                      return (
                        <div
                          key={likelihoodVal}
                          className={`relative rounded-md border p-1 flex flex-wrap items-center justify-center gap-1 transition-all ${
                            isCriticalZone
                              ? 'bg-rose-950/45 border-rose-800/60 shadow-[inset_0_0_12px_rgba(225,29,72,0.12)] hover:border-rose-500/80 hover:bg-rose-950/60'
                              : isHighZone
                              ? 'bg-amber-950/40 border-amber-800/60 shadow-[inset_0_0_12px_rgba(245,158,11,0.10)] hover:border-amber-500/80 hover:bg-amber-950/55'
                              : isMedZone
                              ? 'bg-yellow-950/25 border-yellow-800/40 shadow-[inset_0_0_8px_rgba(234,179,8,0.06)] hover:border-yellow-500/70 hover:bg-yellow-950/40'
                              : 'bg-emerald-950/25 border-emerald-800/40 shadow-[inset_0_0_8px_rgba(16,185,129,0.06)] hover:border-emerald-500/70 hover:bg-emerald-950/40'
                          }`}
                        >
                          <span className="absolute top-1 right-1 text-[8px] font-mono-tech font-semibold opacity-40 select-none pointer-events-none text-slate-400">
                            {score}
                          </span>
                          {findingsInCell.map((finding) => (
                            <motion.button
                              key={finding.id}
                              whileHover={{ scale: 1.15 }}
                              onClick={() => {
                                setSelectedFinding(finding);
                                setExpandedFeedId(finding.id);
                              }}
                              className={`px-2 py-1 rounded text-[10px] font-mono-tech font-bold cursor-pointer transition-all shadow-md ${getSeverityBadgeColor(
                                finding.severity
                              )} ${
                                selectedFinding?.id === finding.id
                                  ? 'ring-2 ring-orange-400 dark:ring-white ring-offset-2 ring-offset-[#080a0f] scale-110 z-20'
                                  : ''
                              }`}
                              title={`${finding.title} (${finding.severity})`}
                            >
                              {finding.category.slice(0, 3)}
                            </motion.button>
                          ))}
                        </div>
                      );
                    })}
                  </div>
                ))}
              </div>

              {/* X-Axis Number Ticks */}
              <div className="grid grid-cols-5 gap-1.5 ml-8 mb-2 relative z-10 text-center">
                {[1, 2, 3, 4, 5].map((lvl) => (
                  <div key={lvl} className="text-[10px] font-mono-tech font-bold text-slate-500">
                    {lvl}
                  </div>
                ))}
              </div>

              {/* X-Axis Label */}
              <div className="text-center ml-8 text-[10px] font-mono-tech uppercase tracking-widest text-slate-400 font-semibold relative z-10 flex items-center justify-center gap-1.5">
                <span>←</span>
                <span>LIKELIHOOD</span>
                <span>→</span>
              </div>
            </div>

            {/* Matrix Legend */}
            <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono-tech text-sentinel-muted pt-2 border-t border-sentinel-border/50">
              <div className="flex items-center gap-3 flex-wrap">
                <span className="flex items-center gap-1.5 font-medium">
                  <span className="w-2.5 h-2.5 rounded bg-rose-600" /> Critical (15-25)
                </span>
                <span className="flex items-center gap-1.5 font-medium">
                  <span className="w-2.5 h-2.5 rounded bg-rose-500" /> High (10-14)
                </span>
                <span className="flex items-center gap-1.5 font-medium">
                  <span className="w-2.5 h-2.5 rounded bg-amber-500" /> Medium (5-9)
                </span>
                <span className="flex items-center gap-1.5 font-medium">
                  <span className="w-2.5 h-2.5 rounded bg-emerald-600" /> Low (1-4)
                </span>
              </div>
              <span className="text-[10px]">Click any plotted node to inspect investigation dossier</span>
            </div>
          </div>

          {/* RIGHT: Selected Finding Details & Technical Dossier (5 Cols) */}
          <div className="lg:col-span-5 panel-technical p-5 rounded-lg space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
              <span className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                Selected Threat Dossier
              </span>
              {selectedFinding && (
                <StatusBadge status={selectedFinding.severity} size="sm" />
              )}
            </div>

            {selectedFinding ? (
              <div className="space-y-4 font-mono-tech text-xs">
                <div>
                  <span className="text-[10px] text-sentinel-muted uppercase block">
                    THREAT VECTOR:
                  </span>
                  <div className="font-bold text-sm text-sentinel-text mt-0.5">
                    {selectedFinding.title}
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3 p-3 bg-sentinel-secondary/40 rounded border border-sentinel-border">
                  <div>
                    <span className="text-[10px] text-sentinel-muted block">AFFECTED SESSION</span>
                    <Link
                      href={`/sessions/${selectedFinding.session}`}
                      className="text-sentinel-copper font-bold hover:underline"
                    >
                      {selectedFinding.session}
                    </Link>
                  </div>
                  <div>
                    <span className="text-[10px] text-sentinel-muted block">DETECTION ENGINE</span>
                    <span className="text-sentinel-text">{selectedFinding.engineType}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-sentinel-muted block">DETECTION STAGE</span>
                    <span className="text-sentinel-text">{selectedFinding.detectedStage}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-sentinel-muted block">DETECTED TIMESTAMP</span>
                    <span className="text-sentinel-muted">{selectedFinding.timestamp}</span>
                  </div>
                </div>

                <div className="p-3 bg-sentinel-secondary/30 border border-sentinel-border rounded space-y-1">
                  <span className="text-[10px] text-sentinel-muted uppercase font-bold block">
                    Deterministic Evidence:
                  </span>
                  <p className="text-sentinel-text leading-relaxed text-[11px]">
                    {selectedFinding.evidence}
                  </p>
                </div>

                <div className="p-3 bg-sentinel-elevated border border-sentinel-border rounded space-y-1">
                  <span className="text-[10px] text-emerald-700 dark:text-sentinel-mint uppercase font-bold block">
                    Mandated Hardening Action:
                  </span>
                  <p className="text-emerald-800 dark:text-sentinel-mint leading-relaxed text-[11px]">
                    {selectedFinding.recommendation}
                  </p>
                </div>
              </div>
            ) : (
              <div className="py-12 text-center text-xs text-sentinel-muted font-mono-tech">
                Select a finding node on the matrix to examine technical telemetry.
              </div>
            )}
          </div>
        </div>

        {/* Section 2: Investigation-Style Findings Feed */}
        <div className="panel-technical p-5 rounded-lg space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-sentinel-copper" />
              <h2 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                Investigation Findings Feed
              </h2>
            </div>
            <span className="text-[10px] font-mono-tech text-sentinel-muted">
              Live Auditing Feed • Expand for Forensic Evidence
            </span>
          </div>

          <div className="space-y-3">
            {threats.map((finding) => {
              const isExpanded = expandedFeedId === finding.id;

              return (
                <div
                  key={finding.id}
                  className="rounded-lg border border-sentinel-border bg-sentinel-secondary/30 overflow-hidden transition-colors"
                >
                  <div
                    onClick={() => toggleFeed(finding.id)}
                    className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer hover:bg-sentinel-elevated/60"
                  >
                    <div className="flex items-center gap-3">
                      <StatusBadge status={finding.severity} size="sm" />
                      <div>
                        <div className="font-mono-tech text-xs font-bold text-sentinel-text">
                          {finding.title}
                        </div>
                        <div className="text-[10px] font-mono-tech text-sentinel-muted mt-0.5">
                          Session: {finding.session} • Detected during {finding.detectedStage} • {finding.engineType}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-3">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          toggleFeed(finding.id);
                        }}
                        className="px-2.5 py-1 rounded bg-sentinel-secondary border border-sentinel-border hover:border-sentinel-copper text-[11px] font-mono-tech text-sentinel-copper transition-colors"
                      >
                        {isExpanded ? 'HIDE EVIDENCE' : 'VIEW EVIDENCE'}
                      </button>
                      <ChevronRight
                        className={`w-4 h-4 text-sentinel-muted transition-transform ${
                          isExpanded ? 'rotate-90' : ''
                        }`}
                      />
                    </div>
                  </div>

                  {/* Expandable Forensic Evidence */}
                  <AnimatePresence>
                    {isExpanded && (
                      <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        exit={{ opacity: 0, height: 0 }}
                        transition={{ duration: 0.2 }}
                        className="px-4 pb-4 pt-1 border-t border-sentinel-border/50 bg-sentinel-secondary/20 space-y-3 font-mono-tech text-xs"
                      >
                        <div className="p-3 rounded bg-sentinel-deep border border-sentinel-border space-y-1">
                          <span className="text-[10px] text-sentinel-muted uppercase font-bold block">
                            Forensic Evidence:
                          </span>
                          <p className="text-sentinel-text text-xs leading-relaxed">
                            {finding.evidence}
                          </p>
                        </div>

                        <div className="p-3 rounded bg-sentinel-elevated border border-sentinel-border space-y-1">
                          <span className="text-[10px] text-emerald-700 dark:text-sentinel-mint uppercase font-bold block">
                            Configuration Recommendation:
                          </span>
                          <p className="text-emerald-800 dark:text-sentinel-mint text-xs leading-relaxed">
                            {finding.recommendation}
                          </p>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              );
            })}
            </div>
          </div>
        </>
      )}
    </div>
  </AppShell>
);
}
