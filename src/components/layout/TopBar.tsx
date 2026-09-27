'use client';

import React, { useState } from 'react';
import {
  Search,
  Bell,
  Plus,
  Command,
  ChevronDown,
  Activity,
  CheckCircle2,
  AlertTriangle,
  FolderGit2,
} from 'lucide-react';
import { ThemeSlider } from './ThemeSlider';

interface TopBarProps {
  onOpenCommandPalette: () => void;
  onStartNewAnalysis: () => void;
}

export const TopBar: React.FC<TopBarProps> = ({
  onOpenCommandPalette,
  onStartNewAnalysis,
}) => {
  const [showNotifications, setShowNotifications] = useState(false);
  const [workspace, setWorkspace] = useState('IND-NCR-GW01');

  return (
    <header className="h-14 border-b border-sentinel-border bg-sentinel-deep px-4 flex items-center justify-between sticky top-0 z-20">
      {/* Left: Context / Workspace switcher */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 px-2.5 py-1 rounded bg-sentinel-secondary border border-sentinel-border text-xs font-mono-tech text-sentinel-muted hover:border-sentinel-copper transition-colors cursor-pointer">
          <FolderGit2 className="w-3.5 h-3.5 text-sentinel-copper" />
          <span className="text-[10px] text-sentinel-muted/80">WORKSPACE:</span>
          <span className="text-sentinel-text font-medium">{workspace}</span>
          <ChevronDown className="w-3 h-3 text-sentinel-muted" />
        </div>

        <div className="hidden md:flex items-center gap-2 text-xs font-mono-tech text-sentinel-muted border-l border-sentinel-border pl-3">
          <span className="text-[10px] text-sentinel-muted/70">ACTIVE SESSION:</span>
          <span className="text-sentinel-copper font-medium">IPSEC-00421</span>
          <span className="w-1.5 h-1.5 rounded-full bg-sentinel-mint" />
        </div>
      </div>

      {/* Center: Command Palette Trigger */}
      <div className="flex-1 max-w-md mx-4">
        <button
          onClick={onOpenCommandPalette}
          className="w-full flex items-center justify-between px-3 py-1.5 rounded bg-sentinel-secondary/60 border border-sentinel-border text-xs text-sentinel-muted hover:border-sentinel-copper/60 hover:text-sentinel-text transition-all group"
        >
          <div className="flex items-center gap-2">
            <Search className="w-3.5 h-3.5 text-sentinel-muted group-hover:text-sentinel-copper" />
            <span className="text-[11px] font-sans">Search sessions, RFC rules, or execute commands...</span>
          </div>
          <div className="flex items-center gap-1 font-mono-tech text-[10px] bg-sentinel-elevated px-1.5 py-0.5 rounded border border-sentinel-border text-sentinel-muted">
            <Command className="w-2.5 h-2.5" />
            <span>K</span>
          </div>
        </button>
      </div>

      {/* Right: Status, Notifications, New Analysis button */}
      <div className="flex items-center gap-3">
        {/* System telemetry indicator */}
        <div className="hidden lg:flex items-center gap-2 px-2.5 py-1 rounded bg-sentinel-elevated border border-sentinel-border text-[11px] font-mono-tech text-sentinel-muted">
          <Activity className="w-3.5 h-3.5 text-sentinel-mint" />
          <span>INFERENCE:</span>
          <span className="text-sentinel-mint font-medium">12ms</span>
          <span className="text-sentinel-border">|</span>
          <span>FASTAPI ADAPTER:</span>
          <span className="text-sentinel-muted">STANDBY</span>
        </div>

        {/* Notifications Popover */}
        <div className="relative">
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="relative p-2 rounded bg-sentinel-secondary/60 border border-sentinel-border text-sentinel-muted hover:text-sentinel-text hover:border-sentinel-copper transition-colors"
            title="Notifications"
          >
            <Bell className="w-4 h-4" />
            <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-sentinel-copper" />
          </button>

          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 bg-sentinel-deep border border-sentinel-border rounded-lg shadow-2xl p-3 z-50 text-xs">
              <div className="flex items-center justify-between pb-2 border-b border-sentinel-border">
                <span className="font-mono-tech font-bold text-sentinel-text uppercase text-[11px]">
                  Alert Stream
                </span>
                <span className="text-[10px] font-mono-tech text-sentinel-muted">3 Unacknowledged</span>
              </div>
              <div className="divide-y divide-sentinel-border/50 py-1">
                <div className="py-2 space-y-1">
                  <div className="flex items-center gap-1.5 text-sentinel-critical font-mono-tech text-[11px]">
                    <AlertTriangle className="w-3 h-3" />
                    <span>Sweet32 Collision Risk</span>
                  </div>
                  <p className="text-[11px] text-sentinel-muted">
                    Session IPSEC-00419 active with 3DES-CBC cipher over 2.1M packets.
                  </p>
                </div>
                <div className="py-2 space-y-1">
                  <div className="flex items-center gap-1.5 text-sentinel-warning font-mono-tech text-[11px]">
                    <AlertTriangle className="w-3 h-3" />
                    <span>Rekey PFS Omission</span>
                  </div>
                  <p className="text-[11px] text-sentinel-muted">
                    Child SA #18418 derived without ephemeral DH exchange.
                  </p>
                </div>
                <div className="py-2 space-y-1">
                  <div className="flex items-center gap-1.5 text-sentinel-mint font-mono-tech text-[11px]">
                    <CheckCircle2 className="w-3 h-3" />
                    <span>RFC Compliance Run Complete</span>
                  </div>
                  <p className="text-[11px] text-sentinel-muted">
                    Evaluated 24 deterministic rules. 18 Passed, 4 Warnings, 2 Failed.
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Theme Slider (Dark / White Mode) */}
        <ThemeSlider />

        {/* Primary "+ New Analysis" Action */}
        <button
          onClick={onStartNewAnalysis}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-sentinel-copper text-sentinel-bg font-mono-tech text-xs font-semibold rounded hover:bg-sentinel-copperHover transition-all shadow-sm active:scale-95"
        >
          <Plus className="w-3.5 h-3.5 stroke-[3]" />
          <span>New Analysis</span>
        </button>
      </div>
    </header>
  );
};
