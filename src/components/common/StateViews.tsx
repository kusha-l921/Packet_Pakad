import React from 'react';
import { Upload, Cpu, AlertTriangle, RefreshCw, Layers } from 'lucide-react';

interface EmptyStateProps {
  title?: string;
  description?: string;
  onUploadPcap?: () => void;
  onCreateTestbed?: () => void;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title = 'NO ACTIVE ANALYSIS',
  description = 'Upload a PCAP capture file or deploy a synthetic testbed to initiate protocol dissection.',
  onUploadPcap,
  onCreateTestbed,
}) => {
  return (
    <div className="flex flex-col items-center justify-center p-12 border border-dashed border-sentinel-border bg-sentinel-deep/50 rounded-lg text-center max-w-xl mx-auto my-12">
      <div className="w-12 h-12 rounded-lg bg-sentinel-secondary flex items-center justify-center text-sentinel-copper mb-4 border border-sentinel-border">
        <Layers className="w-6 h-6" />
      </div>
      <h3 className="font-mono-tech text-sm tracking-widest text-sentinel-text uppercase font-semibold mb-2">
        {title}
      </h3>
      <p className="text-xs text-sentinel-muted max-w-sm mb-6 leading-relaxed">
        {description}
      </p>
      <div className="flex items-center gap-3">
        {onUploadPcap && (
          <button
            onClick={onUploadPcap}
            className="flex items-center gap-2 px-3.5 py-2 bg-sentinel-copper text-sentinel-bg font-mono-tech text-xs font-semibold rounded hover:bg-sentinel-copperHover transition-colors"
          >
            <Upload className="w-3.5 h-3.5" />
            UPLOAD PCAP
          </button>
        )}
        {onCreateTestbed && (
          <button
            onClick={onCreateTestbed}
            className="flex items-center gap-2 px-3.5 py-2 bg-sentinel-elevated border border-sentinel-border text-sentinel-text font-mono-tech text-xs font-semibold rounded hover:border-sentinel-copper transition-colors"
          >
            <Cpu className="w-3.5 h-3.5 text-sentinel-copper" />
            CREATE TESTBED
          </button>
        )}
      </div>
    </div>
  );
};

interface LoadingStateProps {
  stage?: string;
  details?: string;
}

export const LoadingState: React.FC<LoadingStateProps> = ({
  stage = 'Evaluating RFC compliance & cryptographic vector posture...',
  details = 'Running rule-based deterministic dissection & statistical classifier models.',
}) => {
  return (
    <div className="flex flex-col items-center justify-center p-12 border border-sentinel-border bg-sentinel-deep rounded-lg text-center max-w-lg mx-auto my-12">
      <div className="relative w-12 h-12 mb-5">
        <div className="absolute inset-0 rounded-full border-2 border-sentinel-border" />
        <div className="absolute inset-0 rounded-full border-2 border-sentinel-copper border-t-transparent animate-spin" />
        <div className="absolute inset-2 rounded-full border border-sentinel-mint/40 border-b-transparent animate-spin [animation-direction:reverse]" />
      </div>
      <div className="font-mono-tech text-xs tracking-wider text-sentinel-copper uppercase font-medium mb-1">
        {stage}
      </div>
      <div className="text-[11px] text-sentinel-muted max-w-xs font-mono-tech">
        {details}
      </div>
    </div>
  );
};

interface ErrorStateProps {
  title?: string;
  reason?: string;
  onRetry?: () => void;
  onViewPackets?: () => void;
  onUploadNew?: () => void;
}

export const ErrorState: React.FC<ErrorStateProps> = ({
  title = 'ANALYSIS FAILED',
  reason = 'Unable to reconstruct IKE session: Incomplete IKE negotiation detected in capture frame sequence.',
  onRetry,
  onViewPackets,
  onUploadNew,
}) => {
  return (
    <div className="flex flex-col items-center justify-center p-8 border border-sentinel-critical/30 bg-sentinel-deep rounded-lg text-center max-w-lg mx-auto my-8">
      <div className="w-10 h-10 rounded-full bg-sentinel-critical/10 border border-sentinel-critical/30 flex items-center justify-center text-sentinel-critical mb-3">
        <AlertTriangle className="w-5 h-5" />
      </div>
      <h3 className="font-mono-tech text-sm tracking-wider text-sentinel-critical uppercase font-bold mb-1">
        {title}
      </h3>
      <p className="text-xs text-sentinel-muted mb-5 leading-relaxed font-mono-tech max-w-md">
        <span className="text-sentinel-text">Reason:</span> {reason}
      </p>
      <div className="flex flex-wrap items-center justify-center gap-2.5">
        {onRetry && (
          <button
            onClick={onRetry}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-sentinel-elevated border border-sentinel-border hover:border-sentinel-copper text-sentinel-text font-mono-tech text-xs rounded transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5 text-sentinel-copper" />
            RETRY ANALYSIS
          </button>
        )}
        {onViewPackets && (
          <button
            onClick={onViewPackets}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-sentinel-secondary border border-sentinel-border text-sentinel-muted hover:text-sentinel-text font-mono-tech text-xs rounded transition-colors"
          >
            VIEW PACKETS
          </button>
        )}
        {onUploadNew && (
          <button
            onClick={onUploadNew}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-sentinel-copper text-sentinel-bg font-mono-tech text-xs font-semibold rounded hover:bg-sentinel-copperHover transition-colors"
          >
            <Upload className="w-3.5 h-3.5" />
            UPLOAD NEW PCAP
          </button>
        )}
      </div>
    </div>
  );
};
