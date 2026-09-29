import React from 'react';

interface TechnicalFieldProps {
  label: string;
  value: string | number | React.ReactNode;
  isMono?: boolean;
  highlight?: boolean;
  copyable?: boolean;
  className?: string;
}

export const TechnicalField: React.FC<TechnicalFieldProps> = ({
  label,
  value,
  isMono = true,
  highlight = false,
  copyable = false,
  className = '',
}) => {
  const [copied, setCopied] = React.useState(false);

  const handleCopy = () => {
    if (typeof value === 'string' || typeof value === 'number') {
      navigator.clipboard.writeText(String(value));
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  };

  return (
    <div className={`flex flex-col gap-0.5 ${className}`}>
      <span className="text-[10px] tracking-wider uppercase font-medium text-sentinel-muted">
        {label}
      </span>
      <div className="flex items-center gap-1.5 group">
        <span
          className={`text-xs ${
            isMono ? 'font-mono-tech' : ''
          } ${highlight ? 'text-sentinel-copper font-medium' : 'text-sentinel-text'}`}
        >
          {value}
        </span>
        {copyable && (
          <button
            onClick={handleCopy}
            title="Copy value"
            className="opacity-0 group-hover:opacity-100 transition-opacity text-[10px] font-mono-tech text-sentinel-muted hover:text-sentinel-copper"
          >
            {copied ? '✓' : '⧉'}
          </button>
        )}
      </div>
    </div>
  );
};

interface ProgressBarProps {
  value: number; // 0 - 100
  max?: number;
  segments?: number;
  color?: 'copper' | 'mint' | 'warning' | 'critical';
  height?: string;
  showLabel?: boolean;
  className?: string;
}

export const ProgressBar: React.FC<ProgressBarProps> = ({
  value,
  max = 100,
  segments,
  color = 'copper',
  height = 'h-1.5',
  showLabel = false,
  className = '',
}) => {
  const pct = Math.min(100, Math.max(0, (value / max) * 100));

  const getColorClass = () => {
    switch (color) {
      case 'mint':
        return 'bg-sentinel-mint';
      case 'warning':
        return 'bg-sentinel-warning';
      case 'critical':
        return 'bg-sentinel-critical';
      case 'copper':
      default:
        return 'bg-sentinel-copper';
    }
  };

  if (segments && segments > 0) {
    const activeSegments = Math.round((pct / 100) * segments);
    return (
      <div className={`flex items-center gap-1 ${className}`}>
        {Array.from({ length: segments }).map((_, i) => (
          <div
            key={i}
            className={`flex-1 ${height} rounded-none transition-all duration-300 ${
              i < activeSegments ? getColorClass() : 'bg-sentinel-border'
            }`}
          />
        ))}
        {showLabel && (
          <span className="font-mono-tech text-[10px] text-sentinel-muted ml-2">
            {Math.round(pct)}%
          </span>
        )}
      </div>
    );
  }

  return (
    <div className={`w-full bg-sentinel-secondary/60 rounded-full overflow-hidden ${className}`}>
      <div
        className={`${height} ${getColorClass()} transition-all duration-500 ease-out`}
        style={{ width: `${pct}%` }}
      />
    </div>
  );
};
