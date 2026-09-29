import React from 'react';
import { RiskLevel, ComplianceStatus } from '@/types';

interface StatusBadgeProps {
  status: RiskLevel | ComplianceStatus | 'ACTIVE' | 'TERMINATED' | 'REKEYING' | 'NEGOTIATING' | 'NORMAL' | 'ANOMALOUS';
  className?: string;
  size?: 'sm' | 'md';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, className = '', size = 'md' }) => {
  const getStyle = () => {
    switch (status) {
      case 'LOW':
      case 'PASSED':
      case 'ACTIVE':
      case 'NORMAL':
        return {
          bg: 'bg-emerald-500/10 dark:bg-sentinel-mint/10',
          text: 'text-emerald-700 dark:text-sentinel-mint font-semibold',
          border: 'border-emerald-500/30 dark:border-sentinel-mint/30',
          dot: 'bg-emerald-600 dark:bg-sentinel-mint',
        };
      case 'MEDIUM':
      case 'WARNING':
      case 'REKEYING':
        return {
          bg: 'bg-amber-500/15 dark:bg-sentinel-warning/10',
          text: 'text-amber-800 dark:text-sentinel-warning font-semibold',
          border: 'border-amber-500/30 dark:border-sentinel-warning/30',
          dot: 'bg-amber-600 dark:bg-sentinel-warning',
        };
      case 'HIGH':
      case 'CRITICAL':
      case 'FAILED':
      case 'ANOMALOUS':
      case 'TERMINATED':
        return {
          bg: 'bg-rose-500/10 dark:bg-sentinel-critical/10',
          text: 'text-rose-700 dark:text-sentinel-critical font-semibold',
          border: 'border-rose-500/30 dark:border-sentinel-critical/30',
          dot: 'bg-rose-600 dark:bg-sentinel-critical',
        };
      case 'NEGOTIATING':
      default:
        return {
          bg: 'bg-orange-500/10 dark:bg-sentinel-copper/10',
          text: 'text-orange-600 dark:text-sentinel-copper font-semibold',
          border: 'border-orange-500/30 dark:border-sentinel-copper/30',
          dot: 'bg-orange-500 dark:bg-sentinel-copper',
        };
    }
  };

  const style = getStyle();
  const sizeClasses = size === 'sm' ? 'px-1.5 py-0.5 text-[11px]' : 'px-2.5 py-1 text-xs';

  return (
    <span
      className={`inline-flex items-center gap-1.5 font-mono-tech uppercase font-medium tracking-wider rounded border ${style.bg} ${style.text} ${style.border} ${sizeClasses} ${className}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${style.dot} animate-pulse`} />
      {status}
    </span>
  );
};
