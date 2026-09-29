import React from 'react';
import { SecurityScore as SecurityScoreType } from '@/types';
import { StatusBadge } from '@/components/common/StatusBadge';

interface MetricStripProps {
  scoreData: SecurityScoreType;
}

export const MetricStrip: React.FC<MetricStripProps> = ({ scoreData }) => {
  return (
    <div className="w-full bg-sentinel-deep border border-sentinel-border rounded-lg overflow-hidden divide-y md:divide-y-0 md:divide-x divide-sentinel-border grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5">
      {/* Metric 1: Security Score */}
      <div className="p-3.5 flex flex-col justify-between">
        <span className="text-[10px] font-mono-tech tracking-wider uppercase text-sentinel-muted">
          Security Score
        </span>
        <div className="flex items-baseline gap-1.5 mt-1">
          <span className="font-mono-tech text-2xl font-bold text-sentinel-text">
            {scoreData.total}
          </span>
          <span className="font-mono-tech text-xs text-sentinel-muted">/ {scoreData.max}</span>
        </div>
      </div>

      {/* Metric 2: Risk Rating */}
      <div className="p-3.5 flex flex-col justify-between">
        <span className="text-[10px] font-mono-tech tracking-wider uppercase text-sentinel-muted">
          Risk Posture
        </span>
        <div className="mt-1">
          <StatusBadge status={scoreData.riskLevel} size="sm" />
        </div>
      </div>

      {/* Metric 3: Compliance */}
      <div className="p-3.5 flex flex-col justify-between">
        <span className="text-[10px] font-mono-tech tracking-wider uppercase text-sentinel-muted">
          RFC Compliance
        </span>
        <div className="flex items-baseline gap-1 mt-1">
          <span className="font-mono-tech text-2xl font-bold text-sentinel-copper">
            {scoreData.compliancePercentage}%
          </span>
          <span className="text-[10px] font-mono-tech text-sentinel-muted">PASSED</span>
        </div>
      </div>

      {/* Metric 4: AI Confidence */}
      <div className="p-3.5 flex flex-col justify-between">
        <span className="text-[10px] font-mono-tech tracking-wider uppercase text-sentinel-muted">
          ML Classifier Confidence
        </span>
        <div className="flex items-baseline gap-1 mt-1">
          <span className="font-mono-tech text-2xl font-bold text-sentinel-mint">
            {scoreData.aiConfidence}%
          </span>
          <span className="text-[10px] font-mono-tech text-sentinel-muted">H.264/RTP</span>
        </div>
      </div>

      {/* Metric 5: Active Sessions */}
      <div className="p-3.5 flex flex-col justify-between col-span-2 sm:col-span-1">
        <span className="text-[10px] font-mono-tech tracking-wider uppercase text-sentinel-muted">
          Active Sessions
        </span>
        <div className="flex items-center justify-between mt-1">
          <span className="font-mono-tech text-2xl font-bold text-sentinel-text">
            {scoreData.activeSessions}
          </span>
          <span className="flex items-center gap-1.5 text-[10px] font-mono-tech text-sentinel-mint">
            <span className="w-1.5 h-1.5 rounded-full bg-sentinel-mint animate-pulse" />
            SYNCHRONIZED
          </span>
        </div>
      </div>
    </div>
  );
};
