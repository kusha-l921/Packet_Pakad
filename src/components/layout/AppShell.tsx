'use client';

import React, { useState } from 'react';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { CommandPalette } from './CommandPalette';
import { AnalysisPipeline } from '@/components/analysis/AnalysisPipeline';
import { Upload, X, CheckCircle2, FileUp } from 'lucide-react';

interface AppShellProps {
  children: React.ReactNode;
}

export const AppShell: React.FC<AppShellProps> = ({ children }) => {
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [analysisModalOpen, setAnalysisModalOpen] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null);
  const [analysisDone, setAnalysisDone] = useState(false);

  const handleStartUpload = (filePlaceholder = 'capture_delhi_border_gw_18k.pcap') => {
    setUploadedFileName(filePlaceholder);
    setIsAnalyzing(true);
    setAnalysisDone(false);
  };

  const handlePipelineComplete = () => {
    setIsAnalyzing(false);
    setAnalysisDone(true);
  };

  return (
    <div className="h-screen w-screen overflow-hidden flex bg-sentinel-bg text-sentinel-text">
      {/* Pinned Fixed Sidebar navigation */}
      <Sidebar />

      {/* Main View Area (Locked header, isolated content scroll) */}
      <div className="flex-1 flex flex-col h-full min-w-0 overflow-hidden">
        <TopBar
          onOpenCommandPalette={() => setCommandPaletteOpen(true)}
          onStartNewAnalysis={() => setAnalysisModalOpen(true)}
        />

        <main className="flex-1 p-6 overflow-y-auto min-h-0 focus:outline-none">
          {children}
        </main>
      </div>

      {/* ⌘ K Command Palette Modal */}
      <CommandPalette
        isOpen={commandPaletteOpen}
        onClose={() => setCommandPaletteOpen(false)}
        onUploadPcapClick={() => {
          setCommandPaletteOpen(false);
          setAnalysisModalOpen(true);
        }}
      />

      {/* New Analysis / Upload PCAP Pipeline Modal */}
      {analysisModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
          <div className="w-full max-w-3xl bg-sentinel-deep border border-sentinel-border rounded-lg shadow-2xl p-6 space-y-5">
            <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
              <div className="flex items-center gap-2">
                <FileUp className="w-5 h-5 text-sentinel-copper" />
                <h3 className="font-mono-tech font-bold text-sm tracking-wider uppercase text-sentinel-text">
                  Initiate IPsec Protocol Dissection
                </h3>
              </div>
              <button
                onClick={() => {
                  setAnalysisModalOpen(false);
                  setIsAnalyzing(false);
                  setUploadedFileName(null);
                  setAnalysisDone(false);
                }}
                className="text-sentinel-muted hover:text-sentinel-text"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {!uploadedFileName ? (
              <div className="space-y-4">
                <p className="text-xs text-sentinel-muted">
                  Ingest raw PCAP / PCAPNG packet capture files for multi-modal reconstruction across Layer 0 through Layer 3.
                </p>

                <div
                  onClick={() => handleStartUpload()}
                  className="border-2 border-dashed border-sentinel-border hover:border-sentinel-copper/60 p-8 rounded-lg flex flex-col items-center justify-center cursor-pointer transition-colors bg-sentinel-secondary/30 group"
                >
                  <div className="w-12 h-12 rounded-lg bg-sentinel-secondary flex items-center justify-center text-sentinel-muted group-hover:text-sentinel-copper transition-colors mb-3">
                    <Upload className="w-6 h-6" />
                  </div>
                  <div className="font-mono-tech text-xs text-sentinel-text font-semibold mb-1">
                    Drag & Drop or Click to Select Capture
                  </div>
                  <div className="text-[11px] text-sentinel-muted">
                    Supports .pcap, .pcapng, tcpdump format (Max 250 MB)
                  </div>
                </div>

                <div className="flex items-center justify-between pt-2">
                  <span className="text-[11px] font-mono-tech text-sentinel-muted">
                    Or run benchmark reference sample:
                  </span>
                  <button
                    onClick={() => handleStartUpload('ntro_ps26160_sample_01.pcap')}
                    className="text-xs font-mono-tech text-sentinel-copper hover:underline"
                  >
                    Load Sample NTRO-26160-Border.pcap
                  </button>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="flex items-center justify-between p-3 rounded bg-sentinel-secondary/60 border border-sentinel-border font-mono-tech text-xs">
                  <span className="text-sentinel-muted">LOADED FILE:</span>
                  <span className="text-sentinel-copper font-medium">{uploadedFileName}</span>
                  <span className="text-sentinel-mint">18.4 MB (18,421 Packets)</span>
                </div>

                {/* Animated Analysis Pipeline */}
                <AnalysisPipeline
                  isRunning={isAnalyzing}
                  onComplete={handlePipelineComplete}
                />

                {analysisDone && (
                  <div className="p-3 rounded bg-sentinel-mint/10 border border-sentinel-mint/30 flex items-center justify-between">
                    <div className="flex items-center gap-2 text-xs font-mono-tech text-sentinel-mint">
                      <CheckCircle2 className="w-4 h-4" />
                      <span>DISSECTION COMPLETE: Session IPSEC-00421 Synthesized (Score: 82/100)</span>
                    </div>
                    <button
                      onClick={() => setAnalysisModalOpen(false)}
                      className="px-3 py-1 bg-sentinel-mint text-sentinel-bg font-mono-tech text-xs font-bold rounded hover:bg-sentinel-mintHover transition-colors"
                    >
                      VIEW DASHBOARD
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
