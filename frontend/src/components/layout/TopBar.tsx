'use client';

import React, { useState } from 'react';
import {
  Search,
  Bell,
  Command,
  CheckCircle2,
  AlertTriangle,
  PanelLeftClose,
  PanelLeftOpen,
} from 'lucide-react';
import { ThemeSlider } from './ThemeSlider';

interface TopBarProps {
  onOpenCommandPalette: () => void;
  onStartNewAnalysis?: () => void;
  isSidebarOpen?: boolean;
  onToggleSidebar?: () => void;
  showSidebarToggle?: boolean;
}

export const TopBar: React.FC<TopBarProps> = ({
  onOpenCommandPalette,
  isSidebarOpen = true,
  onToggleSidebar,
  showSidebarToggle = false,
}) => {
  const [showNotifications, setShowNotifications] = useState(false);

  return (
    <header className="h-14 border-b border-sentinel-border bg-sentinel-deep px-4 md:px-6 flex items-center justify-between sticky top-0 z-20 gap-4">
      {/* Sidebar Toggle Button (if enabled) */}
      {showSidebarToggle && (
        <button
          onClick={onToggleSidebar}
          title={isSidebarOpen ? "Hide Sidebar (Ctrl+B)" : "Unhide Sidebar (Ctrl+B)"}
          className="p-2 rounded-lg bg-sentinel-secondary/60 border border-sentinel-border text-sentinel-muted hover:text-sentinel-text hover:border-sentinel-copper transition-colors flex items-center justify-center flex-shrink-0"
        >
          {isSidebarOpen ? (
            <PanelLeftClose className="w-4 h-4" />
          ) : (
            <PanelLeftOpen className="w-4 h-4 text-sentinel-copper" />
          )}
        </button>
      )}

      {/* Search Bar - Oval Browser-style */}
      <div className="flex-1 max-w-xl">
        <button
          onClick={onOpenCommandPalette}
          className="w-full h-9 flex items-center justify-between px-4 rounded-full bg-sentinel-secondary/60 border border-sentinel-border hover:border-sentinel-copper/60 hover:bg-sentinel-secondary text-xs text-sentinel-muted hover:text-sentinel-text transition-all group shadow-inner"
        >
          <div className="flex items-center gap-2.5 truncate">
            <Search className="w-4 h-4 text-sentinel-muted group-hover:text-sentinel-copper transition-colors flex-shrink-0" />
            <span className="text-xs font-sans text-sentinel-muted group-hover:text-sentinel-text truncate">
              Search sessions, RFC rules, or execute commands...
            </span>
          </div>
          <div className="flex items-center gap-1 font-mono-tech text-[10px] bg-sentinel-elevated px-2 py-0.5 rounded-full border border-sentinel-border text-sentinel-muted flex-shrink-0 ml-2">
            <Command className="w-2.5 h-2.5" />
            <span>K</span>
          </div>
        </button>
      </div>

      {/* Right: Bell Icon & Light/Dark Mode */}
      <div className="flex items-center gap-3">
        {/* Notifications Popover */}
        <div className="relative">
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="relative p-2 rounded-full bg-sentinel-secondary/60 border border-sentinel-border text-sentinel-muted hover:text-sentinel-text hover:border-sentinel-copper transition-colors flex items-center justify-center"
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

        {/* Light & Dark Mode Slider */}
        <ThemeSlider />
      </div>
    </header>
  );
};
