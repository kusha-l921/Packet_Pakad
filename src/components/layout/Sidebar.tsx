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
  AlertOctagon,
  FileText,
  Database,
  Settings,
  Shield,
  User,
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
      { name: 'Dashboard', href: '/', icon: LayoutDashboard },
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

export const Sidebar: React.FC = () => {
  const pathname = usePathname();

  const isSelected = (href: string) => {
    if (href === '/') {
      return pathname === '/';
    }
    return pathname.startsWith(href);
  };

  return (
    <aside className="w-64 flex-shrink-0 bg-sentinel-deep border-r border-sentinel-border flex flex-col h-full select-none z-30">
      {/* Brand Header - Pinned */}
      <div className="flex-shrink-0 p-4 border-b border-sentinel-border flex items-center gap-3">
        <div className="w-8 h-8 rounded bg-sentinel-secondary border border-sentinel-border flex items-center justify-center text-sentinel-copper">
          <Shield className="w-4 h-4" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono-tech font-bold text-sm tracking-wide text-sentinel-text">
              IPSEC SENTINEL
            </span>
            <span className="text-[10px] font-mono-tech px-1 py-0.2 rounded bg-sentinel-copper/15 text-sentinel-copper border border-sentinel-copper/30">
              NTRO
            </span>
          </div>
          <div className="text-[11px] text-sentinel-muted tracking-tight">
            IPsec Security Intelligence
          </div>
        </div>
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

        <div className="flex items-center justify-between px-2 py-1.5 rounded bg-sentinel-secondary/40 border border-sentinel-border">
          <div className="flex items-center gap-2 overflow-hidden">
            <div className="w-6 h-6 rounded-full bg-sentinel-border flex items-center justify-center text-sentinel-muted">
              <User className="w-3.5 h-3.5" />
            </div>
            <div className="truncate">
              <div className="text-[11px] font-medium text-sentinel-text truncate">
                Analyst: G. Rao
              </div>
              <div className="text-[10px] text-sentinel-muted truncate font-mono-tech">
                NTRO-SEC-OPS
              </div>
            </div>
          </div>
          <span className="text-[9px] font-mono-tech px-1.5 py-0.5 rounded bg-sentinel-elevated border border-sentinel-border text-sentinel-muted">
            SECRET
          </span>
        </div>
      </div>
    </aside>
  );
};
