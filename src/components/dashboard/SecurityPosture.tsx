'use client';

import React from 'react';
import { Shield, KeyRound, CheckSquare, EyeOff, RotateCcw } from 'lucide-react';
import { SecurityScore as SecurityScoreType } from '@/types';
import { ProgressBar } from '@/components/common/TechnicalField';

interface SecurityPostureProps {
  posture: SecurityScoreType['posture'];
}

export const SecurityPosture: React.FC<SecurityPostureProps> = ({ posture }) => {
  return (
    <div className="panel-technical p-5 rounded-lg flex flex-col justify-between">
      <div>
        <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-sentinel-copper" />
            <span className="text-[10px] font-mono-tech tracking-wider uppercase text-sentinel-text font-semibold">
              SECURITY POSTURE ATTRIBUTES
            </span>
          </div>
          <span className="text-[10px] font-mono-tech text-sentinel-mint bg-sentinel-mint/10 px-1.5 py-0.5 rounded border border-sentinel-mint/30">
            SOVEREIGN STANDARD
          </span>
        </div>

        <div className="space-y-4 my-4">
          {/* Cryptographic Strength */}
          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs font-mono-tech">
              <span className="text-sentinel-muted flex items-center gap-1.5">
                <KeyRound className="w-3.5 h-3.5 text-sentinel-copper" />
                Cryptographic Strength
              </span>
              <span className="text-sentinel-mint font-semibold">
                {posture.cryptoStrength}
              </span>
            </div>
            <ProgressBar value={92} segments={10} color="mint" height="h-1.5" />
          </div>

          {/* Configuration Compliance */}
          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs font-mono-tech">
              <span className="text-sentinel-muted flex items-center gap-1.5">
                <CheckSquare className="w-3.5 h-3.5 text-sentinel-copper" />
                Configuration Compliance
              </span>
              <span className="text-sentinel-text font-semibold">
                {posture.configurationCompliance}%
              </span>
            </div>
            <ProgressBar
              value={posture.configurationCompliance}
              segments={10}
              color="copper"
              height="h-1.5"
            />
          </div>

          {/* Forward Secrecy */}
          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs font-mono-tech">
              <span className="text-sentinel-muted flex items-center gap-1.5">
                <RotateCcw className="w-3.5 h-3.5 text-sentinel-copper" />
                Forward Secrecy (PFS)
              </span>
              <span className="text-sentinel-mint font-semibold">
                {posture.forwardSecrecy ? 'ENABLED (DEGRADED REKEY)' : 'DISABLED'}
              </span>
            </div>
            <ProgressBar value={80} segments={10} color="copper" height="h-1.5" />
          </div>

          {/* Replay Protection */}
          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs font-mono-tech">
              <span className="text-sentinel-muted flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5 text-sentinel-mint" />
                Anti-Replay (ESN 64-bit)
              </span>
              <span className="text-sentinel-mint font-semibold">
                {posture.replayProtection ? 'ENABLED' : 'DISABLED'}
              </span>
            </div>
            <ProgressBar value={100} segments={10} color="mint" height="h-1.5" />
          </div>

          {/* Metadata Exposure */}
          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs font-mono-tech">
              <span className="text-sentinel-muted flex items-center gap-1.5">
                <EyeOff className="w-3.5 h-3.5 text-sentinel-warning" />
                Metadata Exposure
              </span>
              <span className="text-sentinel-warning font-semibold">
                {posture.metadataExposure}
              </span>
            </div>
            <ProgressBar value={60} segments={10} color="warning" height="h-1.5" />
          </div>
        </div>
      </div>

      <div className="pt-2 border-t border-sentinel-border text-[11px] font-mono-tech text-sentinel-muted/80 flex items-center justify-between">
        <span>Framework: NTRO-RFC-C3</span>
        <span>Hardening Delta: -18 pts</span>
      </div>
    </div>
  );
};
