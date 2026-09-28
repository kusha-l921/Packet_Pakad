'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { 
  Shield, 
  LayoutDashboard, 
  Sliders, 
  Radio, 
  GitMerge, 
  FileCheck, 
  Lock, 
  Binary, 
  ShieldAlert, 
  FileSpreadsheet, 
  Database, 
  Settings, 
  Sun, 
  Moon, 
  Search, 
  Bell, 
  Plus, 
  ChevronDown, 
  User, 
  Terminal,
  Activity
} from 'lucide-react';
import { useTheme } from '@/lib/theme/ThemeProvider';

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { theme, toggleTheme } = useTheme();
  const [searchQuery, setSearchQuery] = useState('');

  const navGroups = [
    {
      group: 'OVERVIEW',
      items: [
        { label: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
      ],
    },
    {
      group: 'TESTING',
      items: [
        { label: 'Testbed', href: '/dashboard/testbed', icon: Sliders },
        { label: 'Packet Capture', href: '/dashboard/packet-capture', icon: Radio },
      ],
    },
    {
      group: 'ANALYSIS',
      items: [
        { label: 'Sessions', href: '/dashboard/sessions', icon: GitMerge },
        { label: 'RFC Compliance', href: '/dashboard/rfc-compliance', icon: FileCheck },
        { label: 'Cryptographic Posture', href: '/dashboard/cryptographic-posture', icon: Lock },
        { label: 'Traffic Intelligence', href: '/dashboard/traffic-intelligence', icon: Binary },
        { label: 'Threat Matrix', href: '/dashboard/threat-matrix', icon: ShieldAlert },
      ],
    },
    {
      group: 'OUTPUT',
      items: [
        { label: 'Reports', href: '/dashboard/reports', icon: FileSpreadsheet },
        { label: 'Dataset', href: '/dashboard/dataset', icon: Database },
      ],
    },
    {
      group: 'SYSTEM',
      items: [
        { label: 'Settings', href: '/dashboard/settings', icon: Settings },
      ],
    },
  ];

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-sentinel-bg text-sentinel-text font-sans antialiased">
      {/* ==================================================== */}
      {/* 1. SIDEBAR (Obsidian / Technical Command Center)     */}
      {/* ==================================================== */}
      <aside className="w-64 shrink-0 flex flex-col justify-between border-r border-sentinel-border bg-[#0B0C0D] select-none">
        <div>
          {/* Logo / Header */}
          <div className="h-16 px-4 flex items-center gap-3 border-b border-sentinel-border">
            <Link href="/" className="flex items-center gap-2.5 group">
              <div className="w-8 h-8 rounded border border-sentinel-copper/60 bg-[#151719] flex items-center justify-center text-sentinel-copper group-hover:border-sentinel-copper transition-colors">
                <Shield className="w-4 h-4 stroke-[1.8]" />
              </div>
              <div className="flex flex-col">
                <div className="flex items-center gap-1.5">
                  <span className="font-bold text-xs tracking-wider uppercase text-sentinel-text">
                    IPSEC SENTINEL
                  </span>
                  <span className="text-[9px] font-mono px-1 py-0.2 rounded border border-sentinel-copper/50 text-sentinel-copper bg-sentinel-copper/10 font-bold leading-tight">
                    NTRO
                  </span>
                </div>
                <span className="text-[10px] font-mono text-sentinel-text-muted tracking-tight">
                  IPsec Security Intelligence
                </span>
              </div>
            </Link>
          </div>

          {/* Navigation Items */}
          <nav className="p-3 space-y-5 overflow-y-auto max-h-[calc(100vh-140px)]">
            {navGroups.map((grp, grpIdx) => (
              <div key={grpIdx} className="space-y-1">
                <div className="px-3 text-[10px] font-mono uppercase tracking-wider text-sentinel-text-muted/70 font-semibold mb-1">
                  {grp.group}
                </div>
                {grp.items.map((item) => {
                  const Icon = item.icon;
                  const isActive = pathname === item.href;
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      className={`flex items-center gap-2.5 px-3 py-2 rounded text-xs font-mono font-medium transition-colors ${
                        isActive
                          ? 'bg-sentinel-copper/15 text-sentinel-copper border-l-2 border-sentinel-copper pl-2.5 font-bold shadow-sm'
                          : 'text-sentinel-text-muted hover:text-sentinel-text hover:bg-sentinel-panel/60'
                      }`}
                    >
                      <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-sentinel-copper' : 'text-sentinel-text-muted'}`} />
                      <span>{item.label}</span>
                    </Link>
                  );
                })}
              </div>
            ))}
          </nav>
        </div>

        {/* Sidebar Footer User Card */}
        <div className="p-3 border-t border-sentinel-border bg-[#101214] font-mono text-xs">
          <div className="flex items-center justify-between text-[10px] text-sentinel-text-muted mb-2 px-1">
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-sentinel-mint animate-pulse" />
              <span>Engine Online</span>
            </span>
            <span className="text-sentinel-copper">v2.4-fast</span>
          </div>

          <div className="flex items-center justify-between p-2 rounded border border-sentinel-border bg-[#151719]">
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 rounded-full bg-sentinel-border/50 flex items-center justify-center text-sentinel-text-muted">
                <User className="w-3.5 h-3.5" />
              </div>
              <div className="text-[11px] leading-tight">
                <div className="font-semibold text-sentinel-text">Analyst: G. Rao</div>
                <div className="text-[9px] text-sentinel-text-muted">NTRO-SEC-OPS</div>
              </div>
            </div>
            <span className="text-[9px] px-1.5 py-0.5 rounded bg-sentinel-border/40 text-sentinel-text-muted font-bold tracking-wider">
              SECRET
            </span>
          </div>
        </div>
      </aside>

      {/* ==================================================== */}
      {/* 2. MAIN VIEWPORT & TOPBAR                            */}
      {/* ==================================================== */}
      <div className="flex-1 flex flex-col min-w-0 h-full overflow-hidden bg-sentinel-bg">
        {/* Top Header Bar */}
        <header className="h-16 shrink-0 border-b border-sentinel-border bg-[#0B0C0D] px-6 flex items-center justify-between gap-4 font-mono text-xs">
          {/* Left: Workspace & Active Session Selectors */}
          <div className="flex items-center gap-3">
            {/* Workspace Selector */}
            <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded border border-sentinel-border bg-[#151719] text-sentinel-text text-xs">
              <Terminal className="w-3.5 h-3.5 text-sentinel-text-muted" />
              <span className="text-sentinel-text-muted text-[10px]">WORKSPACE:</span>
              <span className="font-semibold">IND-NCR-GW01</span>
              <ChevronDown className="w-3 h-3 text-sentinel-text-muted ml-0.5" />
            </div>

            {/* Active Session Indicator */}
            <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1.5 rounded border border-sentinel-border/80 bg-[#101214] text-xs">
              <span className="text-sentinel-text-muted text-[10px]">ACTIVE SESSION:</span>
              <span className="text-sentinel-copper font-bold">IPSEC-00421</span>
              <span className="w-1.5 h-1.5 rounded-full bg-sentinel-mint animate-pulse ml-1" />
            </div>
          </div>

          {/* Center: Search Bar */}
          <div className="relative flex-1 max-w-md hidden md:block">
            <Search className="w-3.5 h-3.5 text-sentinel-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search sessions, RFC rules, or execute commands..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-12 py-1.5 rounded border border-sentinel-border bg-[#151719] text-sentinel-text placeholder:text-sentinel-text-muted text-xs focus:outline-none focus:border-sentinel-copper/70"
            />
            <kbd className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[10px] text-sentinel-text-muted border border-sentinel-border/70 rounded px-1.5 py-0.5 bg-[#101214]">
              ⌘ K
            </kbd>
          </div>

          {/* Right: Engine Telemetry & Actions */}
          <div className="flex items-center gap-3">
            {/* Live Inference Indicator */}
            <div className="hidden xl:flex items-center gap-2 text-[11px] text-sentinel-text-muted px-2 py-1 rounded border border-sentinel-border/50 bg-[#101214]">
              <Activity className="w-3.5 h-3.5 text-sentinel-mint" />
              <span>INFERENCE: <strong className="text-sentinel-text">12ms</strong></span>
              <span className="text-sentinel-border">|</span>
              <span className="text-[10px]">FASTAPI ADAPTER: <strong className="text-sentinel-mint">STANDBY</strong></span>
            </div>

            {/* Notification Bell */}
            <button
              aria-label="System Notifications"
              className="relative w-8 h-8 rounded border border-sentinel-border hover:border-sentinel-copper/50 bg-[#151719] flex items-center justify-center text-sentinel-text-muted hover:text-sentinel-text transition-colors"
            >
              <Bell className="w-3.5 h-3.5" />
              <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full bg-sentinel-copper" />
            </button>

            {/* Theme Toggle */}
            <button
              onClick={toggleTheme}
              aria-label="Toggle Theme"
              className="w-8 h-8 rounded border border-sentinel-border hover:border-sentinel-copper/50 bg-[#151719] flex items-center justify-center text-sentinel-text-muted hover:text-sentinel-text transition-colors"
            >
              {theme === 'dark' ? (
                <Sun className="w-3.5 h-3.5 text-sentinel-copper" />
              ) : (
                <Moon className="w-3.5 h-3.5 text-sentinel-copper" />
              )}
            </button>

            {/* New Analysis CTA */}
            <button className="flex items-center gap-1.5 px-3 py-1.5 rounded uppercase tracking-wider font-semibold border border-sentinel-copper bg-sentinel-copper text-white dark:text-[#0B0C0D] hover:bg-sentinel-copper/90 transition-colors text-xs">
              <Plus className="w-3.5 h-3.5 stroke-[2.5]" />
              <span>New Analysis</span>
            </button>
          </div>
        </header>

        {/* Content Area with smooth scroll */}
        <main className="flex-1 overflow-y-auto p-6 bg-sentinel-bg">
          <div className="max-w-7xl mx-auto">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
