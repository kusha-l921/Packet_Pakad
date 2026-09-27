'use client';

import React, { useEffect, useState } from 'react';
import { motion, useSpring, useTransform } from 'framer-motion';
import { ShieldAlert, ShieldCheck, Info, CheckCircle2 } from 'lucide-react';
import { SecurityScore as SecurityScoreType } from '@/types';
import { StatusBadge } from '@/components/common/StatusBadge';
import { ProgressBar } from '@/components/common/TechnicalField';

interface SecurityScoreProps {
  scoreData: SecurityScoreType;
}

export const SecurityScore: React.FC<SecurityScoreProps> = ({ scoreData }) => {
  const [hasAnimated, setHasAnimated] = useState(false);

  // Animated count-up for score
  const springValue = useSpring(0, {
    stiffness: 40,
    damping: 18,
    duration: 1.2,
  });

  const displayScore = useTransform(springValue, (current) => Math.round(current));
  const [currentVal, setCurrentVal] = useState(0);

  useEffect(() => {
    springValue.set(scoreData.total);
    const unsubscribe = displayScore.on('change', (latest) => {
      setCurrentVal(latest);
    });
    setHasAnimated(true);
    return () => unsubscribe();
  }, [scoreData.total, springValue, displayScore]);

  const breakdownItems = [
    { label: 'Cryptography', current: scoreData.breakdown.cryptography.current, max: scoreData.breakdown.cryptography.max },
    { label: 'RFC Compliance', current: scoreData.breakdown.compliance.current, max: scoreData.breakdown.compliance.max },
    { label: 'SA Security', current: scoreData.breakdown.saSecurity.current, max: scoreData.breakdown.saSecurity.max },
    { label: 'Anti-Replay', current: scoreData.breakdown.replayProtection.current, max: scoreData.breakdown.replayProtection.max },
    { label: 'Forward Secrecy', current: scoreData.breakdown.pfs.current, max: scoreData.breakdown.pfs.max },
    { label: 'Metadata Leakage', current: scoreData.breakdown.metadataExposure.current, max: scoreData.breakdown.metadataExposure.max },
  ];

  return (
    <div className="panel-technical p-5 rounded-lg flex flex-col justify-between">
      <div>
        {/* Top Header */}
        <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
          <div>
            <div className="text-[10px] font-mono-tech tracking-wider uppercase text-sentinel-muted">
              CURRENT SECURITY ASSESSMENT
            </div>
            <div className="flex items-center gap-2 mt-0.5">
              <span className="font-mono-tech font-bold text-sentinel-copper text-sm">
                {scoreData.targetId}
              </span>
              <span className="text-[11px] text-sentinel-muted">
                • Analyzed {scoreData.assessedAt}
              </span>
            </div>
          </div>
          <StatusBadge status={scoreData.riskLevel} />
        </div>

        {/* Score & Gauge Display */}
        <div className="flex items-baseline gap-2 my-5">
          <motion.div className="font-mono-tech text-5xl font-bold text-sentinel-text tracking-tight">
            {currentVal}
          </motion.div>
          <div className="font-mono-tech text-base text-sentinel-muted">
            / {scoreData.max}
          </div>
          <div className="ml-auto text-right">
            <span className="text-[11px] font-mono-tech text-sentinel-warning uppercase block">
              {scoreData.riskLevel} RISK POSTURE
            </span>
            <span className="text-[10px] text-sentinel-muted">
              NTRO Benchmark C3
            </span>
          </div>
        </div>

        {/* Overall Progress Gauge */}
        <ProgressBar
          value={scoreData.total}
          max={scoreData.max}
          color={scoreData.total > 85 ? 'mint' : scoreData.total > 70 ? 'warning' : 'critical'}
          height="h-2"
          className="mb-5"
        />
      </div>

      {/* Breakdown Grid */}
      <div className="pt-3 border-t border-sentinel-border">
        <div className="text-[10px] font-mono-tech tracking-wider uppercase text-sentinel-muted mb-2.5">
          DETERMINISTIC SCORE BREAKDOWN
        </div>
        <div className="grid grid-cols-2 gap-x-4 gap-y-2.5">
          {breakdownItems.map((item) => (
            <div key={item.label} className="space-y-1">
              <div className="flex items-center justify-between text-[11px] font-mono-tech">
                <span className="text-sentinel-muted truncate">{item.label}</span>
                <span className="text-sentinel-text font-medium">
                  {item.current}
                  <span className="text-sentinel-muted/60">/{item.max}</span>
                </span>
              </div>
              <ProgressBar
                value={item.current}
                max={item.max}
                color={
                  item.current / item.max >= 0.8
                    ? 'mint'
                    : item.current / item.max >= 0.6
                    ? 'copper'
                    : 'critical'
                }
                height="h-1"
              />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
