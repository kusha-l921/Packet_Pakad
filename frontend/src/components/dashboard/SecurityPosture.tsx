'use client';

import React from 'react';
import { Shield, KeyRound, CheckSquare, EyeOff, RotateCcw } from 'lucide-react';
import { SecurityScore as SecurityScoreType } from '@/types';
import { ProgressBar } from '@/components/common/TechnicalField';

interface SecurityPostureProps {
  posture: SecurityScoreType['posture'];
}

export const SecurityPosture: React.FC<SecurityPostureProps> = ({ posture }) => {
  const cryptoVal =
    posture.cryptoStrength === 'STRONG'
      ? 95
      : posture.cryptoStrength === 'ACCEPTABLE'
      ? 75
      : posture.cryptoStrength === 'WEAK'
      ? 45
      : 18;

  const cryptoColor: 'mint' | 'copper' | 'warning' =
    posture.cryptoStrength === 'STRONG'
      ? 'mint'
      : posture.cryptoStrength === 'ACCEPTABLE'
      ? 'copper'
      : 'warning';

  const cryptoTextColor =
    posture.cryptoStrength === 'STRONG'
      ? 'text-sentinel-mint'
      : posture.cryptoStrength === 'ACCEPTABLE'
      ? 'text-sentinel-copper'
      : posture.cryptoStrength === 'WEAK'
      ? 'text-sentinel-warning'
      : 'text-red-400';

  const metadataVal =
    posture.metadataExposure === 'LOW'
      ? 85
      : posture.metadataExposure === 'MEDIUM'
      ? 55
      : 20;

  const metadataColor: 'mint' | 'copper' | 'warning' =
    posture.metadataExposure === 'LOW'
      ? 'mint'
      : posture.metadataExposure === 'MEDIUM'
      ? 'copper'
      : 'warning';

  const metadataTextColor =
    posture.metadataExposure === 'LOW'
      ? 'text-sentinel-mint'
      : posture.metadataExposure === 'MEDIUM'
      ? 'text-sentinel-copper'
      : 'text-sentinel-warning';

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
            SECURITY BASELINE
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
              <span className={`font-semibold ${cryptoTextColor}`}>
                {posture.cryptoStrength}
              </span>
            </div>
            <ProgressBar value={cryptoVal} segments={10} color={cryptoColor} height="h-1.5" />
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
              color={posture.configurationCompliance >= 85 ? 'mint' : 'copper'}
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
              <span className={`font-semibold ${posture.forwardSecrecy ? 'text-sentinel-mint' : 'text-sentinel-warning'}`}>
                {posture.forwardSecrecy ? 'ENABLED (STRICT EPHEMERAL)' : 'DISABLED'}
              </span>
            </div>
            <ProgressBar
              value={posture.forwardSecrecy ? 100 : 0}
              segments={10}
              color={posture.forwardSecrecy ? 'mint' : 'warning'}
              height="h-1.5"
            />
          </div>

          {/* Replay Protection */}
          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs font-mono-tech">
              <span className="text-sentinel-muted flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5 text-sentinel-mint" />
                Anti-Replay (ESN 64-bit)
              </span>
              <span className={`font-semibold ${posture.replayProtection ? 'text-sentinel-mint' : 'text-sentinel-copper'}`}>
                {posture.replayProtection ? 'ENABLED (ESN 64-bit)' : 'STANDARD 32-bit (ESN Inactive)'}
              </span>
            </div>
            <ProgressBar
              value={posture.replayProtection ? 100 : 50}
              segments={10}
              color={posture.replayProtection ? 'mint' : 'copper'}
              height="h-1.5"
            />
          </div>

          {/* Metadata Exposure Risk */}
          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs font-mono-tech">
              <span className="text-sentinel-muted flex items-center gap-1.5">
                <EyeOff className="w-3.5 h-3.5 text-sentinel-warning" />
                Metadata Leakage Risk
              </span>
              <span className={`font-semibold ${metadataTextColor}`}>
                {posture.metadataExposure} RISK
              </span>
            </div>
            <ProgressBar value={metadataVal} segments={10} color={metadataColor} height="h-1.5" />
          </div>
        </div>
      </div>
    </div>
  );
};
