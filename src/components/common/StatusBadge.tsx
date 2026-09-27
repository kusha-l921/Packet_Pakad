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
          bg: 'bg-sentinel-mint/10',
          text: 'text-sentinel-mint',
          border: 'border-sentinel-mint/30',
          dot: 'bg-sentinel-mint',
        };
      case 'MEDIUM':
      case 'WARNING':
      case 'REKEYING':
        return {
          bg: 'bg-sentinel-warning/10',
          text: 'text-sentinel-warning',
          border: 'border-sentinel-warning/30',
          dot: 'bg-sentinel-warning',
        };
      case 'HIGH':
      case 'CRITICAL':
      case 'FAILED':
      case 'ANOMALOUS':
      case 'TERMINATED':
        return {
          bg: 'bg-sentinel-critical/10',
          text: 'text-sentinel-critical',
          border: 'border-sentinel-critical/30',
          dot: 'bg-sentinel-critical',
        };
      case 'NEGOTIATING':
      default:
        return {
          bg: 'bg-sentinel-copper/10',
          text: 'text-sentinel-copper',
          border: 'border-sentinel-copper/30',
          dot: 'bg-sentinel-copper',
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
