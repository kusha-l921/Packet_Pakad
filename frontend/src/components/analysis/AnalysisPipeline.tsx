'use client';

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Check,
  Loader2,
  AlertCircle,
  Clock,
  Sparkles,
  Cpu,
  BrainCircuit,
  Binary,
} from 'lucide-react';
import { PIPELINE_STAGES } from '@/lib/api/analysis';

interface AnalysisPipelineProps {
  isRunning?: boolean;
  onComplete?: () => void;
  interactive?: boolean;
}

export const AnalysisPipeline: React.FC<AnalysisPipelineProps> = ({
  isRunning = false,
  onComplete,
  interactive = false,
}) => {
  const [activeStageIndex, setActiveStageIndex] = useState(isRunning ? 0 : 7); // Default stage 7 (all earlier complete)
  const [statusText, setStatusText] = useState(
    'Correlating cryptographic vector posture with behavioural metadata findings...'
  );

  useEffect(() => {
    if (!isRunning) return;

    let currentIndex = 0;
    const interval = setInterval(() => {
      currentIndex += 1;
      if (currentIndex < PIPELINE_STAGES.length) {
        setActiveStageIndex(currentIndex);
        setStatusText(PIPELINE_STAGES[currentIndex].defaultMsg);
      } else {
        clearInterval(interval);
        if (onComplete) onComplete();
      }
    }, 900);

    return () => clearInterval(interval);
  }, [isRunning, onComplete]);

  const getEngineBadge = (engine: 'RULE' | 'ML' | 'RAG') => {
    switch (engine) {
      case 'RULE':
        return (
          <span className="text-[9px] font-mono-tech px-1 py-0.5 rounded bg-sentinel-secondary border border-sentinel-border text-sentinel-muted">
            RULE ENGINE
          </span>
        );
      case 'ML':
        return (
          <span className="text-[9px] font-mono-tech px-1 py-0.5 rounded bg-sentinel-copper/10 border border-sentinel-copper/30 text-sentinel-copper">
            ML MODEL
          </span>
        );
      case 'RAG':
        return (
          <span className="text-[9px] font-mono-tech px-1 py-0.5 rounded bg-sentinel-mint/10 border border-sentinel-mint/30 text-sentinel-mint">
            DEEP AUDIT
          </span>
        );
    }
  };

  return (
    <div className="p-4 bg-sentinel-deep border border-sentinel-border rounded-lg space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-sentinel-border pb-3">
        <div className="flex items-center gap-2">
          <Binary className="w-4 h-4 text-sentinel-copper" />
          <span className="font-mono-tech text-xs font-semibold text-sentinel-text uppercase tracking-wider">
            Analysis Pipeline Execution
          </span>
          <span className="text-[10px] font-mono-tech px-1.5 py-0.5 rounded bg-sentinel-secondary text-sentinel-muted">
            SUITE-C3
          </span>
        </div>
        <div className="flex items-center gap-2">
          {isRunning ? (
            <span className="flex items-center gap-1.5 text-[11px] font-mono-tech text-sentinel-copper">
              <Loader2 className="w-3 h-3 animate-spin" />
              EXECUTING STAGE {activeStageIndex + 1} OF {PIPELINE_STAGES.length}
            </span>
          ) : (
            <span className="flex items-center gap-1.5 text-[11px] font-mono-tech text-sentinel-mint">
              <Check className="w-3.5 h-3.5" />
              PIPELINE SYNCHRONIZED
            </span>
          )}
        </div>
      </div>

      {/* Pipeline Stage Bar */}
      <div className="grid grid-cols-3 sm:grid-cols-5 lg:grid-cols-9 gap-1.5">
        {PIPELINE_STAGES.map((stage, idx) => {
          const isCompleted = idx < activeStageIndex || (!isRunning && activeStageIndex >= PIPELINE_STAGES.length - 1);
          const isActive = isRunning && idx === activeStageIndex;
          const isPending = idx > activeStageIndex && isRunning;

          return (
            <div
              key={stage.id}
              className={`p-2 rounded border flex flex-col justify-between transition-all min-h-[72px] ${
                isActive
                  ? 'border-sentinel-copper bg-sentinel-copper/10 shadow-sm animate-pulse-slow'
                  : isCompleted
                  ? 'border-sentinel-mint/30 bg-sentinel-mint/5'
                  : 'border-sentinel-border bg-sentinel-secondary/30 opacity-60'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="font-mono-tech text-[10px] text-sentinel-muted">
                  0{idx + 1}
                </span>
                {isActive ? (
                  <Loader2 className="w-3 h-3 text-sentinel-copper animate-spin" />
                ) : isCompleted ? (
                  <Check className="w-3 h-3 text-sentinel-mint" />
                ) : (
                  <Clock className="w-3 h-3 text-sentinel-muted/60" />
                )}
              </div>
              <div className="my-1">
                <div
                  className={`font-mono-tech text-[10px] font-semibold tracking-tight uppercase truncate ${
                    isActive
                      ? 'text-sentinel-copper'
                      : isCompleted
                      ? 'text-sentinel-text'
                      : 'text-sentinel-muted'
                  }`}
                  title={stage.name}
                >
                  {stage.name}
                </div>
              </div>
              <div>{getEngineBadge(stage.engine)}</div>
            </div>
          );
        })}
      </div>

      {/* Real-time status ticker message */}
      <div className="flex items-center gap-2 p-2.5 rounded bg-sentinel-elevated border border-sentinel-border text-xs font-mono-tech text-sentinel-text">
        <span className="text-sentinel-copper font-bold">$</span>
        <span className="text-sentinel-muted">[telemetry]</span>
        <span className="text-sentinel-text truncate">{statusText}</span>
        {isRunning && <span className="inline-block w-1.5 h-3 bg-sentinel-copper animate-blink ml-1" />}
      </div>
    </div>
  );
};
