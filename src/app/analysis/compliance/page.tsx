'use client';

import React, { useState } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import { mockComplianceFindings } from '@/data/findings';
import { StatusBadge } from '@/components/common/StatusBadge';
import { motion } from 'framer-motion';
import {
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Filter,
  Download,
  BookOpen,
} from 'lucide-react';

export default function CompliancePage() {
  const [selectedStatus, setSelectedStatus] = useState<string>('ALL');
  const [expandedRule, setExpandedRule] = useState<string | null>('comp-2');

  const passedCount = 18;
  const warningsCount = 4;
  const failedCount = 2;
  const totalCount = passedCount + warningsCount + failedCount;
  const complianceScore = 87;

  const filteredRules = mockComplianceFindings.filter(
    (rule) => selectedStatus === 'ALL' || rule.status === selectedStatus
  );

  const toggleRule = (id: string) => {
    setExpandedRule(expandedRule === id ? null : id);
  };

  return (
    <AppShell>
      <div className="space-y-6 max-w-7xl mx-auto">
        {/* Page Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-sentinel-border">
          <div>
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-sentinel-copper" />
              <h1 className="font-mono-tech text-base md:text-lg font-bold tracking-wider text-sentinel-text uppercase">
                RFC Compliance & Telemetry Engine
              </h1>
            </div>
            <p className="text-xs text-sentinel-muted mt-0.5">
              Deterministic verification against RFC 7296 (IKEv2), RFC 4303 (ESP), RFC 8221, and NTRO Sovereign Baseline.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                const blob = new Blob([JSON.stringify(mockComplianceFindings, null, 2)], {
                  type: 'application/json',
                });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'rfc_compliance_findings.json';
                a.click();
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-sentinel-secondary border border-sentinel-border hover:border-sentinel-copper text-xs font-mono-tech text-sentinel-muted hover:text-sentinel-text transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              Export Rule Audit JSON
            </button>
          </div>
        </div>

        {/* Top Metric Strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="panel-technical p-4 rounded-lg space-y-1">
            <span className="text-[10px] font-mono-tech tracking-wider uppercase text-sentinel-muted">
              RFC Compliance Score
            </span>
            <div className="flex items-baseline gap-1">
              <span className="font-mono-tech text-3xl font-bold text-sentinel-copper">
                {complianceScore}%
              </span>
              <span className="text-xs font-mono-tech text-sentinel-muted">/ 100%</span>
            </div>
            <div className="text-[10px] font-mono-tech text-sentinel-muted">
              Framework: Sovereign C3
            </div>
          </div>

          <div className="panel-technical p-4 rounded-lg space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono-tech tracking-wider uppercase text-sentinel-muted">
                Passed Rules
              </span>
              <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-mint" />
            </div>
            <div className="font-mono-tech text-3xl font-bold text-sentinel-mint">
              {passedCount}
            </div>
            <div className="text-[10px] font-mono-tech text-sentinel-muted">
              Verified compliant
            </div>
          </div>

          <div className="panel-technical p-4 rounded-lg space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono-tech tracking-wider uppercase text-sentinel-muted">
                Warnings
              </span>
              <AlertTriangle className="w-3.5 h-3.5 text-sentinel-warning" />
            </div>
            <div className="font-mono-tech text-3xl font-bold text-sentinel-warning">
              {warningsCount}
            </div>
            <div className="text-[10px] font-mono-tech text-sentinel-muted">
              Operational degradation
            </div>
          </div>

          <div className="panel-technical p-4 rounded-lg space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono-tech tracking-wider uppercase text-sentinel-muted">
                Failed Rules
              </span>
              <XCircle className="w-3.5 h-3.5 text-sentinel-critical" />
            </div>
            <div className="font-mono-tech text-3xl font-bold text-sentinel-critical">
              {failedCount}
            </div>
            <div className="text-[10px] font-mono-tech text-sentinel-muted">
              Immediate action required
            </div>
          </div>
        </div>

        {/* Filter Bar */}
        <div className="flex items-center justify-between gap-3 p-3 bg-sentinel-deep border border-sentinel-border rounded-lg text-xs font-mono-tech">
          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-sentinel-copper" />
            <span className="text-sentinel-muted uppercase text-[11px]">Filter by Status:</span>
            {(['ALL', 'PASSED', 'WARNING', 'FAILED'] as const).map((status) => (
              <button
                key={status}
                onClick={() => setSelectedStatus(status)}
                className={`px-2 py-0.5 rounded border transition-colors ${
                  selectedStatus === status
                    ? 'border-sentinel-copper bg-sentinel-copper/20 text-sentinel-copper font-bold'
                    : 'border-sentinel-border bg-sentinel-secondary text-sentinel-muted hover:text-sentinel-text'
                }`}
              >
                {status}
              </button>
            ))}
          </div>

          <span className="text-sentinel-muted text-[11px]">
            Engine: Deterministic State Machine (Zero Hallucination)
          </span>
        </div>

        {/* Technical Rule Table */}
        <div className="panel-technical rounded-lg overflow-hidden border border-sentinel-border">
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono-tech text-xs border-collapse">
              <thead className="bg-sentinel-secondary/60 text-sentinel-muted text-[10px] uppercase border-b border-sentinel-border tracking-wider">
                <tr>
                  <th className="py-3 px-4 w-32">Rule ID</th>
                  <th className="py-3 px-4 w-40">Standard Ref</th>
                  <th className="py-3 px-4">Rule Description</th>
                  <th className="py-3 px-4 w-32">Status</th>
                  <th className="py-3 px-4 w-32">Session</th>
                  <th className="py-3 px-4 w-28 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sentinel-border">
                {filteredRules.map((rule) => {
                  const isExpanded = expandedRule === rule.id;

                  return (
                    <React.Fragment key={rule.id}>
                      <tr
                        onClick={() => toggleRule(rule.id)}
                        className={`cursor-pointer transition-colors ${
                          isExpanded
                            ? 'bg-sentinel-elevated'
                            : 'hover:bg-sentinel-elevated/70'
                        }`}
                      >
                        <td className="py-3 px-4 font-bold text-sentinel-copper">
                          {rule.ruleId}
                        </td>
                        <td className="py-3 px-4 text-sentinel-muted">
                          {rule.rfcRef}
                        </td>
                        <td className="py-3 px-4 text-sentinel-text font-sans">
                          {rule.description}
                        </td>
                        <td className="py-3 px-4">
                          <StatusBadge status={rule.status} size="sm" />
                        </td>
                        <td className="py-3 px-4 text-sentinel-muted">
                          {rule.detectedInSession}
                        </td>
                        <td className="py-3 px-4 text-right">
                          <button className="text-sentinel-muted hover:text-sentinel-copper inline-flex items-center gap-1">
                            {isExpanded ? (
                              <ChevronDown className="w-4 h-4 text-sentinel-copper" />
                            ) : (
                              <ChevronRight className="w-4 h-4" />
                            )}
                          </button>
                        </td>
                      </tr>

                      {/* Expandable Technical Evidence & Remediation */}
                      {isExpanded && (
                        <tr className="bg-sentinel-deep/90 border-b border-sentinel-border">
                          <td colSpan={6} className="p-4 space-y-3 font-mono-tech text-xs">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              <div className="p-3 rounded bg-sentinel-secondary/50 border border-sentinel-border space-y-1">
                                <span className="text-[10px] text-sentinel-muted uppercase font-bold block">
                                  Technical Evidence Log:
                                </span>
                                <p className="text-sentinel-text leading-relaxed text-[11px]">
                                  {rule.evidence}
                                </p>
                              </div>

                              <div className="p-3 rounded bg-sentinel-secondary/50 border border-sentinel-border space-y-1">
                                <span className="text-[10px] text-sentinel-mint uppercase font-bold block">
                                  Recommended Hardening Action:
                                </span>
                                <p className="text-sentinel-mint leading-relaxed text-[11px]">
                                  {rule.recommendation}
                                </p>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
