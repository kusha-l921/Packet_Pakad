'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search,
  Upload,
  Radio,
  Cpu,
  FileText,
  AlertOctagon,
  ShieldCheck,
  Binary,
  Activity,
  Network,
  X,
  ArrowRight,
} from 'lucide-react';

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onUploadPcapClick: () => void;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  isOpen,
  onClose,
  onUploadPcapClick,
}) => {
  const [query, setQuery] = useState('');
  const router = useRouter();

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        if (isOpen) {
          onClose();
        } else {
          // Open triggered from parent or toggle
        }
      }
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  const commands = [
    {
      id: 'sessions',
      title: 'Search Sessions',
      subtitle: 'Inspect live IKEv1/IKEv2 Security Associations and flows',
      icon: Network,
      action: () => router.push('/sessions'),
      category: 'NAVIGATION',
    },
    {
      id: 'findings',
      title: 'Search Findings',
      subtitle: 'Review deterministic RFC violations and ML anomaly alerts',
      icon: AlertOctagon,
      action: () => router.push('/threats'),
      category: 'ANALYSIS',
    },
    {
      id: 'upload',
      title: 'Upload PCAP',
      subtitle: 'Ingest raw network packet capture for multi-stage dissection',
      icon: Upload,
      action: () => onUploadPcapClick(),
      category: 'INGESTION',
    },
    {
      id: 'capture',
      title: 'Start Live Capture',
      subtitle: 'Stream promiscuous mode interface packets directly to parser',
      icon: Radio,
      action: () => router.push('/capture'),
      category: 'INGESTION',
    },
    {
      id: 'testbed',
      title: 'Create Testbed',
      subtitle: 'Configure automated synthetic VPN topology and traffic matrix',
      icon: Cpu,
      action: () => router.push('/testbed'),
      category: 'SIMULATION',
    },
    {
      id: 'reports',
      title: 'Open Reports',
      subtitle: 'View executive security summaries and technical dossiers',
      icon: FileText,
      action: () => router.push('/reports'),
      category: 'OUTPUT',
    },
    {
      id: 'threats',
      title: 'Open Threat Matrix',
      subtitle: 'Interactively evaluate likelihood versus impact of protocol findings',
      icon: AlertOctagon,
      action: () => router.push('/threats'),
      category: 'ANALYSIS',
    },
    {
      id: 'compliance',
      title: 'RFC Compliance Rules',
      subtitle: 'View 24 deterministic verification rules and evidence links',
      icon: ShieldCheck,
      action: () => router.push('/analysis/compliance'),
      category: 'ANALYSIS',
    },
    {
      id: 'crypto',
      title: 'Cryptographic Posture',
      subtitle: 'Normalized vector scoring and post-quantum similarity analysis',
      icon: Binary,
      action: () => router.push('/analysis/crypto'),
      category: 'ANALYSIS',
    },
    {
      id: 'traffic',
      title: 'Traffic Intelligence',
      subtitle: 'Statistical temporal packet burst rate and ML classification',
      icon: Activity,
      action: () => router.push('/analysis/traffic'),
      category: 'ANALYSIS',
    },
  ];

  const filteredCommands = commands.filter(
    (c) =>
      c.title.toLowerCase().includes(query.toLowerCase()) ||
      c.subtitle.toLowerCase().includes(query.toLowerCase()) ||
      c.category.toLowerCase().includes(query.toLowerCase())
  );

  const handleSelect = (action: () => void) => {
    onClose();
    action();
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-start justify-center pt-24 px-4 bg-black/70 backdrop-blur-sm">
          <motion.div
            initial={{ opacity: 0, scale: 0.96, y: -10 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.96, y: -10 }}
            transition={{ duration: 0.15, ease: 'easeOut' }}
            className="w-full max-w-xl bg-sentinel-deep border border-sentinel-border rounded-lg shadow-2xl overflow-hidden flex flex-col"
          >
            {/* Search Input Bar */}
            <div className="flex items-center px-4 py-3 border-b border-sentinel-border bg-sentinel-secondary/30">
              <Search className="w-4 h-4 text-sentinel-copper mr-3" />
              <input
                type="text"
                autoFocus
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Type a command or search..."
                className="w-full bg-transparent text-sm text-sentinel-text placeholder:text-sentinel-muted focus:outline-none font-sans"
              />
              <button
                onClick={onClose}
                className="text-sentinel-muted hover:text-sentinel-text p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Commands List */}
            <div className="max-h-96 overflow-y-auto p-2 space-y-1">
              {filteredCommands.length === 0 ? (
                <div className="py-8 text-center text-xs font-mono-tech text-sentinel-muted">
                  No matching protocol commands or sessions found.
                </div>
              ) : (
                filteredCommands.map((command) => {
                  const Icon = command.icon;
                  return (
                    <button
                      key={command.id}
                      onClick={() => handleSelect(command.action)}
                      className="w-full flex items-center justify-between p-2.5 rounded hover:bg-sentinel-elevated text-left group transition-colors border border-transparent hover:border-sentinel-border"
                    >
                      <div className="flex items-center gap-3">
                        <div className="w-7 h-7 rounded bg-sentinel-secondary border border-sentinel-border flex items-center justify-center text-sentinel-muted group-hover:text-sentinel-copper group-hover:border-sentinel-copper/50 transition-colors">
                          <Icon className="w-3.5 h-3.5" />
                        </div>
                        <div>
                          <div className="text-xs font-medium text-sentinel-text group-hover:text-sentinel-copper transition-colors">
                            {command.title}
                          </div>
                          <div className="text-[11px] text-sentinel-muted">
                            {command.subtitle}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono-tech text-[9px] uppercase px-1.5 py-0.5 rounded bg-sentinel-secondary text-sentinel-muted">
                          {command.category}
                        </span>
                        <ArrowRight className="w-3 h-3 text-sentinel-muted group-hover:text-sentinel-copper group-hover:translate-x-0.5 transition-all" />
                      </div>
                    </button>
                  );
                })
              )}
            </div>

            {/* Footer with key hints */}
            <div className="px-3 py-2 border-t border-sentinel-border bg-sentinel-secondary/20 flex items-center justify-between text-[10px] font-mono-tech text-sentinel-muted">
              <div className="flex items-center gap-2">
                <span>Navigation: <kbd className="px-1 py-0.5 bg-sentinel-elevated rounded">↑</kbd> <kbd className="px-1 py-0.5 bg-sentinel-elevated rounded">↓</kbd></span>
                <span>Select: <kbd className="px-1 py-0.5 bg-sentinel-elevated rounded">ENTER</kbd></span>
              </div>
              <div>
                <span>Exit: <kbd className="px-1 py-0.5 bg-sentinel-elevated rounded">ESC</kbd></span>
              </div>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
};
