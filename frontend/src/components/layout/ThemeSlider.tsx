'use client';

import React from 'react';
import { useTheme } from './ThemeContext';
import { motion } from 'framer-motion';
import { Moon, Sun } from 'lucide-react';

interface ThemeSliderProps {
  className?: string;
  showLabels?: boolean;
}

export const ThemeSlider: React.FC<ThemeSliderProps> = ({
  className = '',
  showLabels = true,
}) => {
  const { theme, setTheme } = useTheme();
  const isLight = theme === 'light';

  return (
    <div
      role="radiogroup"
      aria-label="Theme mode switcher"
      className={`inline-flex items-center p-1 rounded-full bg-sentinel-secondary border border-sentinel-border select-none shadow-inner ${className}`}
    >
      {/* Dark Mode Slider Option */}
      <button
        type="button"
        role="radio"
        aria-checked={!isLight}
        onClick={() => setTheme('dark')}
        className={`relative flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono-tech transition-colors duration-200 z-10 ${
          !isLight
            ? 'text-sentinel-text font-bold'
            : 'text-sentinel-muted hover:text-sentinel-text'
        }`}
        title="Switch to Dark Obsidian Mode"
      >
        {!isLight && (
          <motion.div
            layoutId="themeSliderKnob"
            className="absolute inset-0 bg-sentinel-elevated rounded-full border border-sentinel-border shadow-sm -z-10"
            transition={{ type: 'spring', stiffness: 450, damping: 32 }}
          />
        )}
        <Moon className={`w-3.5 h-3.5 ${!isLight ? 'text-sentinel-copper' : 'text-sentinel-muted'}`} />
        {showLabels && <span className="text-[11px] tracking-wider uppercase">Dark</span>}
      </button>

      {/* Light / White Mode Slider Option */}
      <button
        type="button"
        role="radio"
        aria-checked={isLight}
        onClick={() => setTheme('light')}
        className={`relative flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono-tech transition-colors duration-200 z-10 ${
          isLight
            ? 'text-sentinel-text font-bold'
            : 'text-sentinel-muted hover:text-sentinel-text'
        }`}
        title="Switch to White Precision Mode"
      >
        {isLight && (
          <motion.div
            layoutId="themeSliderKnob"
            className="absolute inset-0 bg-sentinel-elevated rounded-full border border-sentinel-border shadow-sm -z-10"
            transition={{ type: 'spring', stiffness: 450, damping: 32 }}
          />
        )}
        <Sun className={`w-3.5 h-3.5 ${isLight ? 'text-sentinel-copper' : 'text-sentinel-muted'}`} />
        {showLabels && <span className="text-[11px] tracking-wider uppercase">White</span>}
      </button>
    </div>
  );
};
