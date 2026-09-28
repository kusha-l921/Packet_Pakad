'use client';

import React from 'react';
import { ArrowRight, Shield, Terminal, ExternalLink } from 'lucide-react';

interface FinalCTAProps {
  onOpenConsole: () => void;
  isTransitioning?: boolean;
}

export default function FinalCTA({ onOpenConsole, isTransitioning }: FinalCTAProps) {
  return (
    <section className="relative py-24 border-b border-sentinel-border/70 bg-[#0B0C0D] overflow-hidden">
      {/* Background wireframe tunnel ring echoes */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none opacity-20">
        <div className="w-[500px] h-[500px] rounded-full border border-sentinel-copper animate-ping duration-1000" />
        <div className="w-[700px] h-[700px] rounded-full border border-sentinel-border" />
        <div className="w-[900px] h-[900px] rounded-full border border-sentinel-mint" />
      </div>

      <div className="relative max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 text-center z-10">
        {/* Eyebrow */}
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-sentinel-border bg-sentinel-panel mb-6">
          <Shield className="w-3.5 h-3.5 text-sentinel-copper" />
          <span className="text-[11px] font-mono tracking-wider text-sentinel-text-muted uppercase">
            SOVEREIGN DEFENSE CRYPTOGRAPHIC ENGINE
          </span>
        </div>

        {/* Heading */}
        <h2 className="text-3xl sm:text-4xl lg:text-5xl font-bold tracking-tight text-sentinel-text mb-6">
          ENTER THE SECURITY CONSOLE.
        </h2>

        {/* Supporting Copy */}
        <p className="text-base sm:text-lg text-sentinel-text-muted max-w-2xl mx-auto mb-10 leading-relaxed font-normal">
          Move from raw encrypted traffic to explainable IPsec security intelligence. 
          Audit live tunnels, analyze cipher suites, verify RFC 7296 compliance, and generate audit-ready reports.
        </p>

        {/* Action Buttons */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-12">
          <button
            onClick={onOpenConsole}
            disabled={isTransitioning}
            className="w-full sm:w-auto px-8 py-4 rounded font-mono text-sm uppercase tracking-wider font-bold border border-sentinel-copper bg-sentinel-copper text-white dark:text-[#0B0C0D] hover:bg-sentinel-copper/90 shadow-xl shadow-sentinel-copper/20 hover:shadow-sentinel-copper/30 transition-all flex items-center justify-center gap-3 group disabled:opacity-75 disabled:cursor-wait"
          >
            <span>{isTransitioning ? 'Entering Tunnel...' : 'Start New Analysis →'}</span>
            <ArrowRight className="w-4 h-4 stroke-[2.5] group-hover:translate-x-1.5 transition-transform" />
          </button>

          <a
            href="#pipeline"
            className="w-full sm:w-auto px-6 py-4 rounded font-mono text-sm uppercase tracking-wider font-semibold border border-sentinel-border hover:border-sentinel-copper/50 bg-sentinel-panel/70 text-sentinel-text hover:text-sentinel-copper transition-all flex items-center justify-center gap-2"
          >
            <span>View Architecture</span>
          </a>
        </div>

        {/* Micro System Footnote */}
        <div className="inline-flex items-center gap-4 text-xs font-mono text-sentinel-text-muted border-t border-sentinel-border/60 pt-6">
          <span>NTRO Problem Statement 26160</span>
          <span>•</span>
          <span>Zero Decryption Required</span>
          <span>•</span>
          <span className="text-sentinel-mint">FastAPI Adapter Ready</span>
        </div>
      </div>
    </section>
  );
}
