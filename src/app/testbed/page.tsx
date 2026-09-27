'use client';

import React, { useState } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import { testbedPresets, testbedDeploymentStages, defaultTestbedConfig } from '@/data/testbed';
import { TestbedConfiguration } from '@/types';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Cpu,
  Layers,
  Play,
  RotateCcw,
  ShieldCheck,
  CheckCircle2,
  Terminal,
  Activity,
  Sliders,
  Send,
  Radio,
  FileCode2,
} from 'lucide-react';
import Link from 'next/link';

export default function TestbedPage() {
  const [config, setConfig] = useState<TestbedConfiguration>(defaultTestbedConfig);
  const [selectedPreset, setSelectedPreset] = useState<string>('NTRO Sovereign Standard');
  const [isDeploying, setIsDeploying] = useState<boolean>(false);
  const [deploymentStageIndex, setDeploymentStageIndex] = useState<number>(-1);
  const [deployedSessionId, setDeployedSessionId] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([
    '[15:40:02] Testbed daemon initialized in network namespace ns_testbed_0.',
    '[15:40:05] Kernel XFRM framework verified. Advanced offload supported.',
  ]);

  const handleApplyPreset = (presetName: string) => {
    const found = testbedPresets.find((p) => p.name === presetName);
    if (found) {
      setSelectedPreset(presetName);
      setConfig({ ...found.config });
      setLogs((prev) => [
        ...prev,
        `[${new Date().toISOString().split('T')[1].slice(0, 8)}] Loaded preset: ${presetName}`,
      ]);
    }
  };

  const handleCreateTestbed = () => {
    setIsDeploying(true);
    setDeploymentStageIndex(0);
    setDeployedSessionId(null);

    let stage = 0;
    const interval = setInterval(() => {
      stage += 1;
      if (stage < testbedDeploymentStages.length) {
        setDeploymentStageIndex(stage);
        setLogs((prev) => [
          ...prev,
          `[${new Date().toISOString().split('T')[1].slice(0, 8)}] [${testbedDeploymentStages[stage].name}] ${testbedDeploymentStages[stage].message}`,
        ]);
      } else {
        clearInterval(interval);
        setIsDeploying(false);
        const newId = `IPSEC-${Math.floor(10000 + Math.random() * 90000)}`;
        setDeployedSessionId(newId);
        setLogs((prev) => [
          ...prev,
          `[${new Date().toISOString().split('T')[1].slice(0, 8)}] [ONLINE] Synthetic topology ready. Ingestion stream ID: ${newId}`,
        ]);
      }
    }, 850);
  };

  // Derive dynamic security expectation based on controls
  const calculateProfile = () => {
    if (config.encryption === 'AES-GCM' && (config.dhGroup === '19' || config.dhGroup === '31') && config.pfs) {
      return {
        category: 'MODERN CLASSICAL',
        security: 'STRONG' as const,
        score: 95,
        color: 'text-sentinel-mint',
      };
    }
    if (config.dhGroup === '21') {
      return {
        category: 'POST-QUANTUM TRANSITIONAL',
        security: 'STRONG' as const,
        score: 98,
        color: 'text-sentinel-copper',
      };
    }
    if (!config.pfs || config.encryption === 'AES-CBC-HMAC') {
      return {
        category: 'LEGACY DEVIATION',
        security: 'ACCEPTABLE' as const,
        score: 72,
        color: 'text-sentinel-warning',
      };
    }
    return {
      category: 'CUSTOM EXPERIMENTAL',
      security: 'ACCEPTABLE' as const,
      score: 80,
      color: 'text-sentinel-text',
    };
  };

  const currentProfile = calculateProfile();

  return (
    <AppShell>
      <div className="space-y-6 max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-sentinel-border">
          <div>
            <div className="flex items-center gap-2">
              <Cpu className="w-5 h-5 text-sentinel-copper" />
              <h1 className="font-mono-tech text-base md:text-lg font-bold tracking-wider text-sentinel-text uppercase">
                IPsec Testbed & Synthetic Dataset Generator
              </h1>
            </div>
            <p className="text-xs text-sentinel-muted mt-0.5">
              Automated virtual lab orchestration for RFC compliance stress-testing and ML dataset synthesis.
            </p>
          </div>

          {/* Quick Preset Selector */}
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono-tech text-sentinel-muted uppercase">
              PRESET:
            </span>
            <div className="flex items-center gap-1.5 flex-wrap">
              {testbedPresets.map((preset) => (
                <button
                  key={preset.name}
                  onClick={() => handleApplyPreset(preset.name)}
                  className={`px-2.5 py-1 text-xs font-mono-tech rounded border transition-all ${
                    selectedPreset === preset.name
                      ? 'bg-sentinel-copper/15 border-sentinel-copper text-sentinel-copper'
                      : 'bg-sentinel-secondary border-sentinel-border text-sentinel-muted hover:text-sentinel-text'
                  }`}
                >
                  {preset.name}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* 2-Column Laboratory Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* LEFT: Configuration Controls (7 Cols) */}
          <div className="lg:col-span-7 panel-technical p-5 rounded-lg space-y-5">
            <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
              <div className="flex items-center gap-2">
                <Sliders className="w-4 h-4 text-sentinel-copper" />
                <span className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                  Configuration Controls
                </span>
              </div>
              <span className="text-[10px] font-mono-tech text-sentinel-muted">
                strongSwan v5.9 / XFRM Engine
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {/* IKE Version */}
              <div className="space-y-1.5">
                <label className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                  IKE Version
                </label>
                <div className="grid grid-cols-2 gap-2">
                  {(['IKEv1', 'IKEv2'] as const).map((v) => (
                    <button
                      key={v}
                      type="button"
                      onClick={() => setConfig({ ...config, ikeVersion: v })}
                      className={`p-2 font-mono-tech text-xs rounded border text-center transition-all ${
                        config.ikeVersion === v
                          ? 'border-sentinel-copper bg-sentinel-copper/15 text-sentinel-copper font-bold'
                          : 'border-sentinel-border bg-sentinel-secondary text-sentinel-muted hover:text-sentinel-text'
                      }`}
                    >
                      {v}
                    </button>
                  ))}
                </div>
              </div>

              {/* IPsec Mode */}
              <div className="space-y-1.5">
                <label className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                  IPsec Mode
                </label>
                <div className="grid grid-cols-2 gap-2">
                  {(['Tunnel', 'Transport'] as const).map((m) => (
                    <button
                      key={m}
                      type="button"
                      onClick={() => setConfig({ ...config, mode: m })}
                      className={`p-2 font-mono-tech text-xs rounded border text-center transition-all ${
                        config.mode === m
                          ? 'border-sentinel-copper bg-sentinel-copper/15 text-sentinel-copper font-bold'
                          : 'border-sentinel-border bg-sentinel-secondary text-sentinel-muted hover:text-sentinel-text'
                      }`}
                    >
                      {m}
                    </button>
                  ))}
                </div>
              </div>

              {/* Encryption Algorithm */}
              <div className="space-y-1.5">
                <label className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                  Symmetric Encryption
                </label>
                <select
                  value={config.encryption}
                  onChange={(e) =>
                    setConfig({ ...config, encryption: e.target.value as any })
                  }
                  className="w-full p-2 bg-sentinel-secondary border border-sentinel-border rounded font-mono-tech text-xs text-sentinel-text focus:outline-none focus:border-sentinel-copper"
                >
                  <option value="AES-GCM">AES-256-GCM (AEAD - Recommended)</option>
                  <option value="AES-256">AES-256-CBC</option>
                  <option value="AES-128">AES-128-CBC</option>
                  <option value="AES-CBC-HMAC">AES-CBC + HMAC-SHA1</option>
                </select>
              </div>

              {/* Authentication */}
              <div className="space-y-1.5">
                <label className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                  Peer Authentication
                </label>
                <select
                  value={config.authentication}
                  onChange={(e) =>
                    setConfig({ ...config, authentication: e.target.value as any })
                  }
                  className="w-full p-2 bg-sentinel-secondary border border-sentinel-border rounded font-mono-tech text-xs text-sentinel-text focus:outline-none focus:border-sentinel-copper"
                >
                  <option value="ECDSA">X.509 ECDSA P-256 Certificate</option>
                  <option value="RSA-SIG">RSA-2048 Digital Signature</option>
                  <option value="PSK">Pre-Shared Key (PSK)</option>
                  <option value="EAP-TLS">EAP-TLS</option>
                </select>
              </div>

              {/* DH Group */}
              <div className="space-y-1.5">
                <label className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                  Diffie-Hellman Key Exchange Group
                </label>
                <select
                  value={config.dhGroup}
                  onChange={(e) =>
                    setConfig({ ...config, dhGroup: e.target.value as any })
                  }
                  className="w-full p-2 bg-sentinel-secondary border border-sentinel-border rounded font-mono-tech text-xs text-sentinel-text focus:outline-none focus:border-sentinel-copper"
                >
                  <option value="19">Group 19 (ECP-256 / NIST P-256)</option>
                  <option value="31">Group 31 (Curve25519 - RFC 8031)</option>
                  <option value="20">Group 20 (ECP-384 / NIST P-384)</option>
                  <option value="21">Group 21 (ECP-521 / NIST P-521)</option>
                  <option value="14">Group 14 (MODP-2048)</option>
                </select>
              </div>

              {/* PFS & IP Version */}
              <div className="space-y-1.5">
                <label className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                  PFS & IP Layer
                </label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setConfig({ ...config, pfs: !config.pfs })}
                    className={`p-2 font-mono-tech text-xs rounded border text-center transition-all ${
                      config.pfs
                        ? 'border-sentinel-mint bg-sentinel-mint/15 text-sentinel-mint font-bold'
                        : 'border-sentinel-border bg-sentinel-secondary text-sentinel-muted'
                    }`}
                  >
                    PFS: {config.pfs ? 'ENABLED' : 'DISABLED'}
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      setConfig({
                        ...config,
                        ipVersion: config.ipVersion === 'IPv4' ? 'IPv6' : 'IPv4',
                      })
                    }
                    className="p-2 font-mono-tech text-xs rounded border border-sentinel-border bg-sentinel-secondary text-sentinel-text text-center hover:border-sentinel-copper"
                  >
                    {config.ipVersion}
                  </button>
                </div>
              </div>
            </div>

            {/* In-Tunnel Traffic Generator Profile */}
            <div className="pt-2 border-t border-sentinel-border space-y-2">
              <label className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                Synthetic Traffic Pattern
              </label>
              <div className="grid grid-cols-5 gap-2">
                {(['Video', 'Web', 'VoIP', 'Email', 'ICMP'] as const).map((t) => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => setConfig({ ...config, trafficType: t })}
                    className={`py-2 px-1 text-center font-mono-tech text-xs rounded border transition-all ${
                      config.trafficType === t
                        ? 'border-sentinel-copper bg-sentinel-copper/15 text-sentinel-copper font-semibold'
                        : 'border-sentinel-border bg-sentinel-secondary text-sentinel-muted hover:text-sentinel-text'
                    }`}
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>

            {/* Action Buttons */}
            <div className="pt-4 border-t border-sentinel-border flex flex-wrap items-center gap-3">
              <button
                disabled={isDeploying}
                onClick={handleCreateTestbed}
                className="flex items-center gap-2 px-4 py-2 bg-sentinel-copper text-sentinel-bg font-mono-tech text-xs font-bold rounded hover:bg-sentinel-copperHover transition-all disabled:opacity-50"
              >
                <Cpu className="w-4 h-4" />
                CREATE TESTBED
              </button>
              <button
                disabled={isDeploying}
                onClick={() => {
                  setLogs((prev) => [
                    ...prev,
                    `[${new Date().toISOString().split('T')[1].slice(0, 8)}] Generating 10,000 synthetic ${config.trafficType} packets @ ${config.packetRate} pps...`,
                  ]);
                }}
                className="flex items-center gap-2 px-3.5 py-2 bg-sentinel-elevated border border-sentinel-border text-sentinel-text font-mono-tech text-xs rounded hover:border-sentinel-copper transition-colors"
              >
                <Send className="w-3.5 h-3.5 text-sentinel-mint" />
                GENERATE TRAFFIC
              </button>
              <Link
                href="/capture"
                className="flex items-center gap-2 px-3.5 py-2 bg-sentinel-secondary border border-sentinel-border text-sentinel-muted hover:text-sentinel-text font-mono-tech text-xs rounded transition-colors"
              >
                <Radio className="w-3.5 h-3.5 text-sentinel-copper" />
                START CAPTURE
              </Link>
            </div>
          </div>

          {/* RIGHT: Live VPN Profile & Deployment Stages (5 Cols) */}
          <div className="lg:col-span-5 space-y-6">
            {/* Live Profile Card */}
            <motion.div
              layout
              className="panel-technical p-5 rounded-lg space-y-4 border-l-4 border-l-sentinel-copper"
            >
              <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-sentinel-copper" />
                  <span className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                    Live VPN Profile Visualizer
                  </span>
                </div>
                <span className="font-mono-tech text-[10px] px-1.5 py-0.5 rounded bg-sentinel-secondary text-sentinel-muted">
                  PREVIEW
                </span>
              </div>

              <div className="space-y-3 font-mono-tech text-xs">
                <div className="flex items-center justify-between py-1 border-b border-sentinel-border/50">
                  <span className="text-sentinel-muted">Negotiation:</span>
                  <span className="text-sentinel-text font-semibold">
                    {config.ikeVersion} ({config.mode} Mode)
                  </span>
                </div>
                <div className="flex items-center justify-between py-1 border-b border-sentinel-border/50">
                  <span className="text-sentinel-muted">Encryption:</span>
                  <span className="text-sentinel-text font-semibold">
                    {config.encryption}
                  </span>
                </div>
                <div className="flex items-center justify-between py-1 border-b border-sentinel-border/50">
                  <span className="text-sentinel-muted">Diffie-Hellman:</span>
                  <span className="text-sentinel-copper font-semibold">
                    DH Group {config.dhGroup}
                  </span>
                </div>
                <div className="flex items-center justify-between py-1 border-b border-sentinel-border/50">
                  <span className="text-sentinel-muted">PFS Enforced:</span>
                  <span className={config.pfs ? 'text-sentinel-mint font-semibold' : 'text-sentinel-critical font-semibold'}>
                    {config.pfs ? 'YES' : 'NO'}
                  </span>
                </div>
                <div className="flex items-center justify-between py-1 border-b border-sentinel-border/50">
                  <span className="text-sentinel-muted">Network Stack:</span>
                  <span className="text-sentinel-text">{config.ipVersion}</span>
                </div>
                <div className="flex items-center justify-between py-1 border-b border-sentinel-border/50">
                  <span className="text-sentinel-muted">Security Profile:</span>
                  <span className={`font-bold ${currentProfile.color}`}>
                    {currentProfile.category}
                  </span>
                </div>
                <div className="flex items-center justify-between pt-1">
                  <span className="text-sentinel-muted">Expected Security:</span>
                  <span className="px-2 py-0.5 rounded bg-sentinel-secondary text-sentinel-mint border border-sentinel-mint/30 font-bold">
                    {currentProfile.security} ({currentProfile.score}/100)
                  </span>
                </div>
              </div>
            </motion.div>

            {/* Deployment Progression Pipeline */}
            <div className="panel-technical p-5 rounded-lg space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-sentinel-border">
                <span className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                  Deployment Progression
                </span>
                {isDeploying && (
                  <span className="font-mono-tech text-[10px] text-sentinel-copper animate-pulse">
                    PROVISIONING...
                  </span>
                )}
                {deployedSessionId && (
                  <span className="font-mono-tech text-[10px] text-sentinel-mint">
                    ACTIVE: {deployedSessionId}
                  </span>
                )}
              </div>

              <div className="space-y-2">
                {testbedDeploymentStages.map((stage, idx) => {
                  const isDone = deploymentStageIndex > idx || (deployedSessionId !== null && !isDeploying);
                  const isCurrent = deploymentStageIndex === idx && isDeploying;

                  return (
                    <div
                      key={stage.id}
                      className={`p-2.5 rounded border text-xs font-mono-tech flex items-center justify-between transition-all ${
                        isCurrent
                          ? 'border-sentinel-copper bg-sentinel-copper/10 text-sentinel-copper'
                          : isDone
                          ? 'border-sentinel-mint/30 bg-sentinel-mint/5 text-sentinel-mint'
                          : 'border-sentinel-border bg-sentinel-secondary/30 text-sentinel-muted opacity-50'
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-sentinel-muted">0{idx + 1}</span>
                        <span className="font-semibold">{stage.name}</span>
                      </div>
                      {isDone ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-mint" />
                      ) : isCurrent ? (
                        <span className="w-2 h-2 rounded-full bg-sentinel-copper animate-ping" />
                      ) : (
                        <span className="text-[10px] text-sentinel-muted">WAITING</span>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        {/* Bottom: Orchestrator Terminal Output */}
        <div className="panel-technical p-4 rounded-lg space-y-2 bg-sentinel-elevated/70 border border-sentinel-border">
          <div className="flex items-center justify-between pb-2 border-b border-sentinel-border/50 text-xs font-mono-tech text-sentinel-muted">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-sentinel-copper" />
              <span className="text-sentinel-text uppercase font-semibold">
                Testbed Orchestrator Console
              </span>
            </div>
            <span>strongSwan /dev/net/tun</span>
          </div>

          <div className="h-32 overflow-y-auto space-y-1 font-mono-tech text-[11px] text-sentinel-muted p-1">
            {logs.map((log, index) => (
              <div key={index} className="leading-relaxed">
                <span className="text-sentinel-copper mr-2">$</span>
                <span className={log.includes('[ONLINE]') ? 'text-sentinel-mint font-semibold' : 'text-sentinel-text'}>
                  {log}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </AppShell>
  );
}
