'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { motion } from 'framer-motion';
import {
  LayoutDashboard,
  Cpu,
  Radio,
  Network,
  ShieldCheck,
  Binary,
  Activity,
  FileCheck2,
  AlertOctagon,
  FileText,
  Database,
  Settings,
  Shield,
  User,
  PanelLeftClose,
} from 'lucide-react';

interface NavItem {
  name: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
}

interface NavGroup {
  label: string;
  items: NavItem[];
}

const navGroups: NavGroup[] = [
  {
    label: 'OVERVIEW',
    items: [
      { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
    ],
  },
  {
    label: 'TESTING',
    items: [
      { name: 'Testbed', href: '/testbed', icon: Cpu },
      { name: 'Packet Capture', href: '/capture', icon: Radio },
    ],
  },
  {
    label: 'ANALYSIS',
    items: [
      { name: 'Sessions', href: '/sessions', icon: Network },
      { name: 'RFC Compliance', href: '/analysis/compliance', icon: ShieldCheck },
      { name: 'Cryptographic Posture', href: '/analysis/crypto', icon: Binary },
      { name: 'Traffic Intelligence', href: '/analysis/traffic', icon: Activity },
      { name: 'Certificate Health', href: '/analysis/certificates', icon: FileCheck2 },
      { name: 'Threat Matrix', href: '/threats', icon: AlertOctagon },
    ],
  },
  {
    label: 'OUTPUT',
    items: [
      { name: 'Reports', href: '/reports', icon: FileText },
      { name: 'Dataset', href: '/dataset', icon: Database },
    ],
  },
  {
    label: 'SYSTEM',
    items: [
      { name: 'Settings', href: '/settings', icon: Settings },
    ],
  },
];

interface SidebarProps {
  onCollapse?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ onCollapse }) => {
  const pathname = usePathname();

  const isSelected = (href: string) => {
    if (href === '/dashboard') {
      return pathname === '/dashboard';
    }
    return pathname.startsWith(href);
  };

  return (
    <aside className="w-64 flex-shrink-0 bg-sentinel-deep border-r border-sentinel-border flex flex-col h-full select-none z-30 transition-all duration-300">
      {/* Brand Header - Pinned */}
      <div className="flex-shrink-0 p-4 border-b border-sentinel-border flex items-center justify-between">
        <Link
          href="/"
          title="Return to Home / Landing Page"
          className="flex items-center gap-2.5 hover:bg-sentinel-secondary/40 transition-colors group cursor-pointer"
        >
          <div className="w-9 h-9 rounded-lg bg-sentinel-secondary/80 border border-sentinel-border flex items-center justify-center p-0.5 group-hover:border-sentinel-copper/60 transition-colors shadow-sm overflow-hidden flex-shrink-0">
            <img
              src="/logo-icon.png"
              alt="Packet Pakad Logo"
              className="w-full h-full object-contain filter drop-shadow-[0_0_8px_rgba(56,189,248,0.3)]"
            />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="font-mono-tech font-bold text-sm tracking-wide text-sentinel-text">
                Packet Pakad
              </span>
            </div>
            <div className="text-[10px] text-sentinel-muted tracking-tight group-hover:text-sentinel-copper transition-colors">
              Security Intelligence
            </div>
          </div>
        </Link>

        {onCollapse && (
          <button
            onClick={onCollapse}
            title="Hide Sidebar (Ctrl+B)"
            className="p-1.5 rounded-lg text-sentinel-muted hover:text-sentinel-text hover:bg-sentinel-secondary transition-colors"
          >
            <PanelLeftClose className="w-4 h-4" />
          </button>
        )}
      </div>

      {/* Navigation list - Pinned container, smooth internal scrolling if needed */}
      <div className="flex-1 overflow-y-auto min-h-0 px-3 py-4 space-y-5">
        {navGroups.map((group) => (
          <div key={group.label} className="space-y-1">
            <div className="px-2 pb-1 text-[10px] font-mono-tech tracking-wider text-sentinel-muted/70 uppercase">
              {group.label}
            </div>
            <div className="space-y-0.5">
              {group.items.map((item) => {
                const active = isSelected(item.href);
                const Icon = item.icon;

                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    target={item.href === '/testbed' ? '_blank' : undefined}
                    rel={item.href === '/testbed' ? 'noopener noreferrer' : undefined}
                    className={`relative flex items-center gap-2.5 px-2.5 py-1.5 rounded text-xs transition-colors group ${
                      active
                        ? 'text-sentinel-text bg-sentinel-copper/10 font-medium'
                        : 'text-sentinel-muted hover:text-sentinel-text hover:bg-sentinel-secondary/50'
                    }`}
                  >
                    {active && (
                      <motion.div
                        layoutId="sidebarActiveIndicator"
                        className="absolute left-0 top-1 bottom-1 w-0.5 bg-sentinel-copper rounded-r"
                        transition={{ type: 'spring', stiffness: 350, damping: 30 }}
                      />
                    )}
                    <Icon
                      className={`w-4 h-4 transition-colors ${
                        active
                          ? 'text-sentinel-copper'
                          : 'text-sentinel-muted group-hover:text-sentinel-text'
                      }`}
                    />
                    <span>{item.name}</span>
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Bottom Status & Profile - Pinned */}
      <div className="flex-shrink-0 p-3 border-t border-sentinel-border bg-sentinel-deep/80 space-y-2">
        <div className="flex items-center justify-between px-2 py-1 text-[11px] font-mono-tech text-sentinel-muted">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-sentinel-mint animate-pulse" />
            <span className="text-sentinel-mint">Engine Online</span>
          </div>
          <span className="text-[10px] text-sentinel-muted/60">v2.4-fast</span>
        </div>

        <div className="flex items-center justify-between px-2 py-1.5 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech text-[10px]">
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-sentinel-copper" />
            <span className="text-sentinel-text font-semibold">TESTBED NODE</span>
          </div>
          <span className="text-sentinel-muted">ETH0</span>
        </div>
      </div>
    </aside>
  );
};
