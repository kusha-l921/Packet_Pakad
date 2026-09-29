'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { motion } from 'framer-motion';
import {
  ShieldCheck,
  Binary,
  Activity,
  FileCheck2,
} from 'lucide-react';

interface AnalysisTabItem {
  name: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  tag?: string;
  description: string;
}

const ANALYSIS_TABS: AnalysisTabItem[] = [
  {
    name: 'RFC Compliance',
    href: '/analysis/compliance',
    icon: ShieldCheck,
    description: 'Deterministic RFC 7296 / 4303 rules',
  },
  {
    name: 'Cryptographic Posture',
    href: '/analysis/crypto',
    icon: Binary,
    description: '19D vector similarity & PQC profiles',
  },
  {
    name: 'Traffic Intelligence',
    href: '/analysis/traffic',
    icon: Activity,
    description: 'Side-channel flow & burst classification',
  },
  {
    name: 'Certificate Health',
    href: '/analysis/certificates',
    icon: FileCheck2,
    tag: 'NEW',
    description: 'X.509 PKI chain & validity telemetry',
  },
];

export const AnalysisTabs: React.FC = () => {
  const pathname = usePathname();

  return (
    <div className="w-full border-b border-sentinel-border bg-sentinel-deep/50 rounded-lg p-1.5 backdrop-blur-sm">
      <nav className="flex items-center gap-1.5 overflow-x-auto scrollbar-none" aria-label="Analysis Tabs">
        {ANALYSIS_TABS.map((tab) => {
          const isActive = pathname === tab.href || pathname?.startsWith(tab.href + '/');
          const Icon = tab.icon;

          return (
            <Link
              key={tab.href}
              href={tab.href}
              className={`relative flex items-center gap-2 px-3.5 py-2 rounded-md font-mono-tech text-xs tracking-wider uppercase transition-all duration-200 select-none whitespace-nowrap group ${
                isActive
                  ? 'text-sentinel-text font-bold bg-sentinel-secondary shadow-xs border border-sentinel-border'
                  : 'text-sentinel-muted hover:text-sentinel-text hover:bg-sentinel-secondary/40 border border-transparent'
              }`}
            >
              {isActive && (
                <motion.div
                  layoutId="analysisActiveIndicator"
                  className="absolute bottom-0 left-2 right-2 h-0.5 bg-sentinel-copper rounded-full"
                  transition={{ type: 'spring', stiffness: 380, damping: 30 }}
                />
              )}
              <Icon
                className={`w-3.5 h-3.5 transition-colors ${
                  isActive ? 'text-sentinel-copper' : 'text-sentinel-muted group-hover:text-sentinel-copper'
                }`}
              />
              <span>{tab.name}</span>

              {tab.tag && (
                <span className="text-[9px] px-1.5 py-0.2 rounded font-bold tracking-tight bg-sentinel-copper/20 text-sentinel-copper border border-sentinel-copper/40">
                  {tab.tag}
                </span>
              )}
            </Link>
          );
        })}
      </nav>
    </div>
  );
};
