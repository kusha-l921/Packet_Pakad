'use client';

import React from 'react';
import Link from 'next/link';
import { Shield, Sun, Moon, ArrowRight, Terminal } from 'lucide-react';
import { useTheme } from '@/lib/theme/ThemeProvider';

interface LandingNavbarProps {
  onOpenConsole: () => void;
  isTransitioning?: boolean;
}

export default function LandingNavbar({ onOpenConsole, isTransitioning }: LandingNavbarProps) {
  const { theme, toggleTheme } = useTheme();

  return (
    <header className="sticky top-0 z-50 w-full border-b border-sentinel-border/80 bg-sentinel-bg/85 backdrop-blur-md transition-colors duration-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-3 group">
          <div className="w-9 h-9 rounded-lg border border-sentinel-copper/60 bg-sentinel-panel flex items-center justify-center p-0.5 group-hover:border-sentinel-copper transition-colors shadow-sm overflow-hidden flex-shrink-0">
            <img
              src="/logo-icon.png"
              alt="Packet Pakad Logo"
              className="w-full h-full object-contain filter drop-shadow-[0_0_8px_rgba(56,189,248,0.3)]"
            />
          </div>
          <div className="flex flex-col">
            <div className="flex items-center gap-2">
              <span className="font-bold text-sm tracking-wider uppercase text-sentinel-text">
                Packet Pakad
              </span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-sentinel-copper/50 text-sentinel-copper bg-sentinel-copper/10 font-semibold leading-tight">
                SECURITY
              </span>
            </div>
            <span className="text-[10px] font-mono text-sentinel-text-muted tracking-tight">
              Packet Pakad Security Intelligence
            </span>
          </div>
        </Link>

        {/* Center Nav Links */}
        <nav className="hidden md:flex items-center gap-7 text-xs font-mono tracking-wide text-sentinel-text-muted">
          <a
            href="#pipeline"
            className="hover:text-sentinel-text transition-colors hover:underline underline-offset-4 decoration-sentinel-copper/60"
          >
            Pipeline
          </a>
          <a
            href="#capabilities"
            className="hover:text-sentinel-text transition-colors hover:underline underline-offset-4 decoration-sentinel-copper/60"
          >
            Capabilities
          </a>
          <a
            href="#architecture"
            className="hover:text-sentinel-text transition-colors hover:underline underline-offset-4 decoration-sentinel-copper/60"
          >
            Architecture
          </a>
          <a
            href="#assessment"
            className="hover:text-sentinel-text transition-colors hover:underline underline-offset-4 decoration-sentinel-copper/60"
          >
            Security Analysis
          </a>
        </nav>

        {/* Right Actions */}
        <div className="flex items-center gap-3">
          {/* Theme Toggle */}
          <button
            onClick={toggleTheme}
            aria-label="Toggle color theme"
            className="w-8 h-8 rounded border border-sentinel-border hover:border-sentinel-copper/50 bg-sentinel-panel flex items-center justify-center text-sentinel-text-muted hover:text-sentinel-text transition-colors"
          >
            {theme === 'dark' ? (
              <Sun className="w-4 h-4 stroke-[1.7] text-sentinel-copper" />
            ) : (
              <Moon className="w-4 h-4 stroke-[1.7] text-sentinel-copper" />
            )}
          </button>

          {/* Open Console CTA */}
          <button
            onClick={onOpenConsole}
            disabled={isTransitioning}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded text-xs font-mono uppercase tracking-wider font-semibold border border-sentinel-copper bg-sentinel-copper text-white dark:text-[#0B0C0D] hover:bg-sentinel-copper/90 hover:shadow-lg transition-all duration-150 disabled:opacity-75 disabled:cursor-wait"
          >
            <span>{isTransitioning ? 'Entering Tunnel...' : 'Open Security Console'}</span>
            <ArrowRight className="w-3.5 h-3.5 stroke-[2]" />
          </button>
        </div>
      </div>
    </header>
  );
}
