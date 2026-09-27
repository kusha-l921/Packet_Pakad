'use client';

import React, { useState } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import { mockThreatFindings } from '@/data/findings';
import { StatusBadge } from '@/components/common/StatusBadge';
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

export default function ThreatMatrixPage() {
  const [selectedFinding, setSelectedFinding] = useState<ThreatFinding | null>(mockThreatFindings[0]);
  const [expandedFeedId, setExpandedFeedId] = useState<string | null>(mockThreatFindings[0].id);

  const toggleFeed = (id: string) => {
    setExpandedFeedId(expandedFeedId === id ? null : id);
  };

  const getSeverityBadgeColor = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-sentinel-critical text-sentinel-bg border-sentinel-critical';
      case 'HIGH':
        return 'bg-sentinel-critical/80 text-sentinel-bg border-sentinel-critical';
      case 'MEDIUM':
        return 'bg-sentinel-warning text-sentinel-bg border-sentinel-warning';
      case 'LOW':
      default:
        return 'bg-sentinel-mint text-sentinel-bg border-sentinel-mint';
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

          <div className="flex items-center gap-2 font-mono-tech text-xs">
            <span className="text-sentinel-muted">ACTIVE THREATS:</span>
            <span className="px-2 py-0.5 rounded bg-sentinel-critical/20 border border-sentinel-critical/40 text-sentinel-critical font-bold">
              {mockThreatFindings.length} Correlated Findings
            </span>
          </div>
        </div>

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

            {/* Matrix Grid Visualization */}
            <div className="relative p-6 bg-sentinel-secondary/30 border border-sentinel-border rounded-lg select-none">
              {/* Y-Axis Label */}
              <div className="absolute left-1.5 top-1/2 -translate-y-1/2 -rotate-90 text-[10px] font-mono-tech uppercase tracking-widest text-sentinel-muted">
                ← IMPACT →
              </div>

              {/* Matrix Cell Grid (5x5) */}
              <div className="grid grid-rows-5 gap-1.5 ml-6 mb-6">
                {[5, 4, 3, 2, 1].map((impactVal) => (
                  <div key={impactVal} className="grid grid-cols-5 gap-1.5 h-14">
                    {[1, 2, 3, 4, 5].map((likelihoodVal) => {
                      const findingsInCell = mockThreatFindings.filter(
                        (f) => f.likelihood === likelihoodVal && f.impact === impactVal
                      );

                      const isCriticalZone = impactVal * likelihoodVal >= 15;
                      const isHighZone = impactVal * likelihoodVal >= 10 && impactVal * likelihoodVal < 15;

                      return (
                        <div
                          key={likelihoodVal}
                          className={`relative rounded border p-1 flex flex-wrap items-center justify-center gap-1 transition-all ${
                            isCriticalZone
                              ? 'bg-sentinel-critical/5 border-sentinel-critical/20'
                              : isHighZone
                              ? 'bg-sentinel-warning/5 border-sentinel-warning/20'
                              : 'bg-sentinel-secondary/30 border-sentinel-border/50'
                          }`}
                        >
                          {findingsInCell.map((finding) => (
                            <motion.button
                              key={finding.id}
                              whileHover={{ scale: 1.15 }}
                              onClick={() => {
                                setSelectedFinding(finding);
                                setExpandedFeedId(finding.id);
                              }}
                              className={`px-2 py-1 rounded text-[10px] font-mono-tech font-bold shadow-md cursor-pointer transition-all ${getSeverityBadgeColor(
                                finding.severity
                              )} ${
                                selectedFinding?.id === finding.id
                                  ? 'ring-2 ring-white scale-110'
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

              {/* X-Axis Label */}
              <div className="text-center ml-6 text-[10px] font-mono-tech uppercase tracking-widest text-sentinel-muted">
                ← LIKELIHOOD →
              </div>
            </div>

            {/* Matrix Legend */}
            <div className="flex flex-wrap items-center justify-between text-[11px] font-mono-tech text-sentinel-muted pt-2 border-t border-sentinel-border/50">
              <div className="flex items-center gap-3">
                <span className="flex items-center gap-1">
                  <span className="w-2.5 h-2.5 rounded bg-sentinel-critical" /> Critical
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-2.5 h-2.5 rounded bg-sentinel-warning" /> High / Med
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-2.5 h-2.5 rounded bg-sentinel-mint" /> Low Risk
                </span>
              </div>
              <span>Click any plotted node to inspect investigation dossier</span>
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
                  <span className="text-[10px] text-sentinel-mint uppercase font-bold block">
                    Mandated Hardening Action:
                  </span>
                  <p className="text-sentinel-mint leading-relaxed text-[11px]">
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
            {mockThreatFindings.map((finding) => {
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
                          <span className="text-[10px] text-sentinel-mint uppercase font-bold block">
                            Configuration Recommendation:
                          </span>
                          <p className="text-sentinel-mint text-xs leading-relaxed">
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
      </div>
    </AppShell>
  );
}
