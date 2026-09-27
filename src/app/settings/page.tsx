'use client';

import React, { useState } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import { API_BASE_URL } from '@/lib/api/client';
import {
  Settings as SettingsIcon,
  Server,
  Shield,
  Sliders,
  CheckCircle2,
  RefreshCw,
  Cpu,
  Save,
  Database,
  Lock,
  Sun,
  Palette,
} from 'lucide-react';
import { ThemeSlider } from '@/components/layout/ThemeSlider';

export default function SettingsPage() {
  const [fastApiUrl, setFastApiUrl] = useState(API_BASE_URL);
  const [anomalyThreshold, setAnomalyThreshold] = useState('0.72');
  const [pfsStrictness, setPfsStrictness] = useState('MANDATORY_ALL');
  const [baselineStandard, setBaselineStandard] = useState('NTRO-2026-C3');
  const [replayWindowSize, setReplayWindowSize] = useState('64');
  const [connectionStatus, setConnectionStatus] = useState<string>('MOCK_ADAPTER_ONLINE');
  const [isSaved, setIsSaved] = useState(false);

  const handleTestConnection = () => {
    setConnectionStatus('PROBING...');
    setTimeout(() => {
      setConnectionStatus('STANDBY (MOCK SERVICE ACTIVE)');
    }, 600);
  };

  const handleSave = () => {
    setIsSaved(true);
    setTimeout(() => setIsSaved(false), 2500);
  };

  return (
    <AppShell>
      <div className="space-y-6 max-w-5xl mx-auto">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-sentinel-border">
          <div>
            <div className="flex items-center gap-2">
              <SettingsIcon className="w-5 h-5 text-sentinel-copper" />
              <h1 className="font-mono-tech text-base md:text-lg font-bold tracking-wider text-sentinel-text uppercase">
                System & Engine Settings
              </h1>
            </div>
            <p className="text-xs text-sentinel-muted mt-0.5">
              Configure analysis parameters, sovereign compliance thresholds, and external FastAPI backend adapter bindings.
            </p>
          </div>

          <button
            onClick={handleSave}
            className="flex items-center gap-2 px-4 py-2 bg-sentinel-copper text-sentinel-bg font-mono-tech text-xs font-bold rounded hover:bg-sentinel-copperHover transition-colors"
          >
            <Save className="w-4 h-4" />
            {isSaved ? 'SETTINGS SAVED ✓' : 'SAVE CONFIGURATION'}
          </button>
        </div>

        {/* Section 1: FastAPI Backend Integration Contract */}
        <div className="panel-technical p-5 rounded-lg space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-sentinel-copper" />
              <h2 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                FastAPI Backend Service Contract
              </h2>
            </div>
            <span className="text-[10px] font-mono-tech text-sentinel-mint">
              ADAPTER READY
            </span>
          </div>

          <div className="space-y-3 font-mono-tech text-xs">
            <div className="space-y-1">
              <label className="text-[10px] uppercase text-sentinel-muted">
                FastAPI REST Service Endpoint URL
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={fastApiUrl}
                  onChange={(e) => setFastApiUrl(e.target.value)}
                  className="flex-1 bg-sentinel-secondary p-2.5 rounded border border-sentinel-border text-sentinel-text focus:outline-none focus:border-sentinel-copper font-mono-tech text-xs"
                />
                <button
                  onClick={handleTestConnection}
                  className="flex items-center gap-1.5 px-3 py-2.5 rounded bg-sentinel-secondary border border-sentinel-border hover:border-sentinel-copper text-sentinel-text font-mono-tech text-xs transition-colors"
                >
                  <RefreshCw className="w-3.5 h-3.5 text-sentinel-copper" />
                  Test Endpoint
                </button>
              </div>
            </div>

            <div className="p-3 rounded bg-sentinel-secondary/40 border border-sentinel-border flex items-center justify-between">
              <div>
                <span className="text-[10px] text-sentinel-muted block">API STATUS:</span>
                <span className="font-bold text-sentinel-copper">{connectionStatus}</span>
              </div>
              <span className="text-[10px] text-sentinel-muted">
                Contract: OpenAPI v3.1 / JSON API Specification
              </span>
            </div>
          </div>
        </div>

        {/* Section 2: Analysis Engine Parameters */}
        <div className="panel-technical p-5 rounded-lg space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
            <div className="flex items-center gap-2">
              <Sliders className="w-4 h-4 text-sentinel-copper" />
              <h2 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                Autonomous Analysis Engine Parameters
              </h2>
            </div>
            <span className="text-[10px] font-mono-tech text-sentinel-muted">
              Layer 3 Engine Configuration
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono-tech text-xs">
            <div className="space-y-1.5">
              <label className="text-[10px] text-sentinel-muted uppercase">
                ML Anomaly Outlier Decision Threshold
              </label>
              <input
                type="text"
                value={anomalyThreshold}
                onChange={(e) => setAnomalyThreshold(e.target.value)}
                className="w-full bg-sentinel-secondary p-2.5 rounded border border-sentinel-border text-sentinel-text focus:outline-none focus:border-sentinel-copper font-mono-tech text-xs"
              />
              <span className="text-[10px] text-sentinel-muted">
                Isolation Forest & Autoencoder combined threshold (Default: 0.72)
              </span>
            </div>

            <div className="space-y-1.5">
              <label className="text-[10px] text-sentinel-muted uppercase">
                Forward Secrecy (PFS) Enforcement Level
              </label>
              <select
                value={pfsStrictness}
                onChange={(e) => setPfsStrictness(e.target.value)}
                className="w-full bg-sentinel-secondary p-2.5 rounded border border-sentinel-border text-sentinel-text focus:outline-none focus:border-sentinel-copper font-mono-tech text-xs"
              >
                <option value="MANDATORY_ALL">Mandatory for Initial Exchange & All Rekey Cycles</option>
                <option value="PERMISSIVE_REKEY">Permissive on Child-SA Rekey Derivations</option>
                <option value="DISABLED">Audit Only (Do not flag warnings)</option>
              </select>
              <span className="text-[10px] text-sentinel-muted">
                Flags warning when Child SA proposal omits ephemeral KE payload.
              </span>
            </div>

            <div className="space-y-1.5">
              <label className="text-[10px] text-sentinel-muted uppercase">
                Sovereign Cryptographic Baseline
              </label>
              <select
                value={baselineStandard}
                onChange={(e) => setBaselineStandard(e.target.value)}
                className="w-full bg-sentinel-secondary p-2.5 rounded border border-sentinel-border text-sentinel-text focus:outline-none focus:border-sentinel-copper font-mono-tech text-xs"
              >
                <option value="NTRO-2026-C3">NTRO 2026-C3 (CNSA Suite / RFC 8221 / Strict AEAD)</option>
                <option value="NIST-SP800-131A">NIST SP 800-131A Revision 2</option>
                <option value="COMMERCIAL-BASELINE">Commercial Enterprise Baseline (Permit AES-CBC)</option>
              </select>
              <span className="text-[10px] text-sentinel-muted">
                Governs automatic deduction weights for deprecated ciphers (3DES/MD5).
              </span>
            </div>

            <div className="space-y-1.5">
              <label className="text-[10px] text-sentinel-muted uppercase">
                Anti-Replay Window Verification Size
              </label>
              <input
                type="text"
                value={replayWindowSize}
                onChange={(e) => setReplayWindowSize(e.target.value)}
                className="w-full bg-sentinel-secondary p-2.5 rounded border border-sentinel-border text-sentinel-text focus:outline-none focus:border-sentinel-copper font-mono-tech text-xs"
              />
              <span className="text-[10px] text-sentinel-muted">
                Minimum bitmap window size required by RFC 4303 (Default: 64 packets)
              </span>
            </div>
          </div>
        </div>

        {/* Section 3: Interface & Display Theme */}
        <div className="panel-technical p-5 rounded-lg space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
            <div className="flex items-center gap-2">
              <Palette className="w-4 h-4 text-sentinel-copper" />
              <h2 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                Display Theme & Visual Identity
              </h2>
            </div>
            <span className="text-[10px] font-mono-tech text-sentinel-mint">
              DYNAMIC THEME ENGINE
            </span>
          </div>

          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded bg-sentinel-secondary/30 border border-sentinel-border font-mono-tech text-xs">
            <div>
              <span className="font-bold text-sentinel-text block">
                Workstation Color Mode
              </span>
              <p className="text-[11px] text-sentinel-muted mt-0.5 max-w-md font-sans">
                Toggle between the Obsidian Tactical Dark environment and the White Architectural Daytime mode. Retains sovereign contrast standards and color-independent badges.
              </p>
            </div>
            <div className="flex-shrink-0">
              <ThemeSlider />
            </div>
          </div>
        </div>

        {/* Section 4: System Information & Build Details */}
        <div className="panel-technical p-5 rounded-lg space-y-3 font-mono-tech text-xs">
          <div className="flex items-center justify-between pb-2 border-b border-sentinel-border">
            <span className="font-bold text-sentinel-text uppercase">
              Application Build Metadata
            </span>
            <span className="text-sentinel-copper">NTRO Problem Statement 26160</span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-[11px] text-sentinel-muted">
            <div>
              <span>PRODUCT:</span> <span className="text-sentinel-text">IPsec Sentinel</span>
            </div>
            <div>
              <span>VERSION:</span> <span className="text-sentinel-text">v2.4.0-production</span>
            </div>
            <div>
              <span>FRONTEND:</span> <span className="text-sentinel-text">Next.js 14 App Router</span>
            </div>
            <div>
              <span>STYLING:</span> <span className="text-sentinel-text">Obsidian / Burnt Copper / Muted Mint</span>
            </div>
            <div>
              <span>ORCHESTRATION:</span> <span className="text-sentinel-text">FastAPI Ready</span>
            </div>
            <div>
              <span>SECURITY AUDIT:</span> <span className="text-sentinel-mint">SOVEREIGN OK</span>
            </div>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
