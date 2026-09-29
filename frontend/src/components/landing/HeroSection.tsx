'use client';

import React from 'react';
import Hero3D from './Hero3D';
import { ArrowRight, ChevronDown } from 'lucide-react';

interface HeroSectionProps {
  onOpenConsole: () => void;
  isTransitioning?: boolean;
}

export default function HeroSection({ onOpenConsole, isTransitioning }: HeroSectionProps) {
  return (
    <section className="relative w-full min-h-[85vh] lg:min-h-[90vh] flex flex-col justify-between pt-6 pb-4 lg:pt-8 lg:pb-6 border-b border-sentinel-border/60 overflow-hidden bg-transparent">
      {/* 
        =============================================================================
        AMBIENT ATMOSPHERE (NO BOUNDARIES, BLENDS SEAMLESSLY INTO PAGE BACKGROUND)
        =============================================================================
      */}
      <div className="absolute top-1/4 right-1/4 w-[600px] h-[600px] bg-sentinel-copper/[0.035] dark:bg-sentinel-copper/[0.05] rounded-full blur-3xl pointer-events-none" />
      <div className="absolute top-1/3 right-1/12 w-[650px] h-[650px] bg-sentinel-mint/[0.025] dark:bg-sentinel-mint/[0.035] rounded-full blur-3xl pointer-events-none" />

      {/* 
        =============================================================================
        3D IPSEC ENVIRONMENT (PRESERVED UNCHANGED)
        =============================================================================
      */}
      <div className="absolute inset-0 w-full h-full pointer-events-auto">
        <Hero3D onTransitionStart={onOpenConsole} isTransitioning={isTransitioning} />
      </div>

      {/* 
        =============================================================================
        DOMINANT EDITORIAL TYPOGRAPHY BLOCK
        - Left margin ≈ 5–6vw on desktop (visual center ≈ 20–25% viewport width)
        - Substantially larger headline (72–88px on desktop, 1.25–1.4x scale)
        - Dedicated spacious width (600–700px), exactly 3 lines, tight leading (0.92)
        - Paragraph: 18–20px desktop, max-w-[560px], 28–36px spacing
        - Buttons & Status Line moved smoothly with text block
        =============================================================================
      */}
      <div className="w-full mx-auto px-6 sm:px-10 lg:pl-[5.5vw] lg:pr-8 xl:pl-[6vw] xl:pr-12 relative z-10 flex-1 flex flex-col justify-center pointer-events-none">
        <div className="max-w-[620px] lg:max-w-[680px] xl:max-w-[720px] select-none">
          {/* Eyebrow badge */}
          <div className="inline-flex items-center gap-2.5 px-3 py-1.5 rounded-full border border-sentinel-copper/40 bg-sentinel-panel/85 backdrop-blur-md w-fit mb-5 pointer-events-auto shadow-sm">
            <img
              src="/logo-icon.png"
              alt="Packet Pakad"
              className="w-4 h-4 object-contain filter drop-shadow-[0_0_6px_rgba(56,189,248,0.5)]"
            />
            <span className="text-[11px] font-mono tracking-wider text-sentinel-text uppercase font-semibold">
              PACKET PAKAD • SOVEREIGN IPSEC INTELLIGENCE
            </span>
          </div>

          {/* 
            Primary Focal Point: Dominant Editorial Display Headline
            72–88px on desktop (lg: ~76px, xl: ~86px, 2xl: ~90px)
            Tight line-height (0.92), negative letter spacing (-0.03em)
            Exactly 3 lines, never wrapping "HIDDEN INSIDE"
          */}
          <h1 className="text-5xl sm:text-6xl md:text-7xl lg:text-[4.75rem] xl:text-[5.4rem] font-extrabold tracking-[-0.03em] leading-[0.92] text-sentinel-text mb-7 lg:mb-8 drop-shadow-sm">
            SEE WHAT'S <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-sentinel-copper via-sentinel-text to-sentinel-copper">
              HIDDEN INSIDE
            </span> <br />
            YOUR VPN.
          </h1>

          {/* Supporting Technical Copy (18–20px desktop, max-w-[560px]) */}
          <p className="text-base sm:text-lg lg:text-[1.125rem] text-sentinel-text-muted leading-relaxed mb-8 max-w-[560px] font-normal pointer-events-auto">
            Analyze IPsec tunnels, reconstruct security sessions, evaluate cryptographic posture, 
            identify encrypted traffic patterns, and generate evidence-grounded security reports — 
            <strong className="text-sentinel-text font-medium"> without decrypting application payloads</strong>.
          </p>

          {/* Inline Action CTAs (24–32px spacing) */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3.5 mb-8 pointer-events-auto">
            <button
              onClick={onOpenConsole}
              disabled={isTransitioning}
              className="px-6 py-3.5 rounded font-mono text-xs uppercase tracking-wider font-semibold border border-sentinel-copper bg-sentinel-copper text-white dark:text-[#0B0C0D] hover:bg-sentinel-copper/90 shadow-lg shadow-sentinel-copper/15 hover:shadow-sentinel-copper/25 transition-all flex items-center justify-center gap-2 group disabled:opacity-75 disabled:cursor-wait"
            >
              <span>{isTransitioning ? 'Entering Tunnel...' : 'Open Security Console'}</span>
              <ArrowRight className="w-4 h-4 stroke-[2] group-hover:translate-x-1 transition-transform" />
            </button>

            <a
              href="#pipeline"
              className="px-5 py-3.5 rounded font-mono text-xs uppercase tracking-wider font-medium border border-sentinel-border hover:border-sentinel-copper/50 bg-sentinel-panel/75 backdrop-blur-sm text-sentinel-text hover:text-sentinel-copper transition-all flex items-center justify-center gap-2"
            >
              <span>Explore Platform</span>
              <ChevronDown className="w-3.5 h-3.5 text-sentinel-text-muted" />
            </a>
          </div>

          {/* Micro Status Strip */}
          <div className="pt-3.5 border-t border-sentinel-border/50 flex items-center justify-between text-[11px] font-mono text-sentinel-text-muted pointer-events-auto max-w-[540px]">
            <div className="flex items-center gap-2">
              <span className="inline-block w-1.5 h-1.5 rounded-full bg-sentinel-mint" />
              <span>SYSTEM READY • IPSEC ENGINE ONLINE</span>
            </div>
            <div className="text-sentinel-copper font-medium">
              RFC 4303 / 7296
            </div>
          </div>
        </div>
      </div>

      {/* 
        =============================================================================
        TELEMETRY CONTINUITY LINK TO PIPELINE
        =============================================================================
      */}
      <div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mt-2 pt-2 flex flex-col items-center justify-center relative z-10 pointer-events-none">
        <a
          href="#pipeline"
          className="group flex flex-col items-center gap-1.5 text-center text-[10px] font-mono tracking-widest uppercase text-sentinel-text-muted hover:text-sentinel-copper transition-colors pointer-events-auto"
        >
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-sentinel-copper animate-ping" />
            <span>DISSECTED TELEMETRY TRANSITIONS TO ANALYTICAL PIPELINE</span>
            <span className="w-1.5 h-1.5 rounded-full bg-sentinel-mint animate-pulse" />
          </div>

          {/* Connected Telemetry Flow Chevron */}
          <div className="flex items-center gap-1 text-[9px] text-sentinel-text-muted/60 group-hover:text-sentinel-copper transition-colors">
            <span>01. CAPTURE</span>
            <span>→</span>
            <span>02. RECONSTRUCT</span>
            <span>→</span>
            <span>03. IDENTIFY</span>
            <span>→</span>
            <span>04. ASSESS</span>
            <span>→</span>
            <span>05. CORRELATE</span>
            <span>→</span>
            <span>06. REPORT</span>
          </div>
          <ChevronDown className="w-3.5 h-3.5 text-sentinel-copper/70 group-hover:translate-y-0.5 transition-transform" />
        </a>
      </div>
    </section>
  );
}
