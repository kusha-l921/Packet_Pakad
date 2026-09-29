'use client';

import React from 'react';
import Link from 'next/link';
import { Play, Radio } from 'lucide-react';

interface NoDataStateProps {
  title?: string;
  description?: string;
  actionText?: string;
  actionHref?: string;
}

export function NoDataState({
  title = "NO DATA TO PROCESS",
  description = "No active IPsec session, encrypted packet stream, or telemetry is currently being processed. Start the virtual testbed to negotiate IKEv2/Child SAs, attach the sniffer, and generate live assessment data.",
  actionText = "LAUNCH TESTBED & START PROCESSING",
  actionHref = "/testbed",
}: NoDataStateProps) {
  return (
    <div className="panel-technical p-8 sm:p-12 rounded-lg border border-sentinel-border bg-sentinel-elevated/40 space-y-6 text-center max-w-4xl mx-auto my-4">
      {/* Cyber Sentinel Shield Animation */}
      <div className="relative w-48 h-48 sm:w-56 sm:h-56 mx-auto flex items-center justify-center select-none">
        <img
          src="/sentinel-shield.gif"
          alt="Sentinel Cryptographic Core Standby"
          className="w-48 h-48 sm:w-56 sm:h-56 rounded-full border border-sentinel-border/80 shadow-[0_0_30px_rgba(196,122,82,0.35)] object-cover"
        />
      </div>

      <div className="space-y-2 max-w-lg mx-auto">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sentinel-secondary border border-sentinel-border text-xs font-mono-tech text-sentinel-warning">
          <Radio className="w-3.5 h-3.5 text-sentinel-copper animate-pulse" />
          STANDBY // WAITING FOR TELEMETRY
        </div>
        <h2 className="text-lg sm:text-xl font-mono-tech font-bold text-sentinel-text uppercase tracking-wider">
          {title}
        </h2>
        <p className="text-xs text-sentinel-muted leading-relaxed font-sans">
          {description}
        </p>
      </div>

      {/* Action Button */}
      <div className="flex items-center justify-center gap-3 pt-2">
        <Link
          href={actionHref}
          className="flex items-center gap-2 px-5 py-2.5 rounded bg-sentinel-copper hover:bg-sentinel-copperHover text-sentinel-bg font-mono-tech text-xs font-bold transition-all shadow-[0_0_20px_rgba(196,122,82,0.3)]"
        >
          <Play className="w-4 h-4 fill-current" />
          {actionText}
        </Link>
      </div>
    </div>
  );
}
