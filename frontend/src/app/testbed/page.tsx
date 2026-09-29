'use client';

import React, { useState, useEffect, useRef } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import {
  testbedDeploymentStages,
  defaultTestbedConfig,
  predefinedIkeSuites,
  predefinedEspSuites,
  ikev2EncryptionTransforms,
  ikev2PrfTransforms,
  ikev2IntegrityTransforms,
  ikev2KeyExchangeTransforms,
  ikev2EsnTransforms,
  PredefinedIkeSuite,
  PredefinedEspSuite,
} from '@/data/testbed';
import { deployTestbed, fetchTestbedLogs, fetchTestbedStatus, triggerTestbedTraffic } from '@/lib/api/testbed';
import { TestbedConfiguration } from '@/types';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Cpu,
  Layers,
  ShieldCheck,
  CheckCircle2,
  Terminal,
  Sliders,
  Send,
  Radio,
  ArrowUpRight,
  RefreshCw,
  Network,
  Lock,
  KeyRound,
  Sparkles,
  ExternalLink,
  ChevronRight,
  ShieldAlert,
  Server,
  Zap,
} from 'lucide-react';
import Link from 'next/link';
import { useSession } from '@/context/SessionContext';

export default function TestbedPage() {
  const { setSelectedSessionId, refreshSessions } = useSession();
  const [config, setConfig] = useState<TestbedConfiguration>(defaultTestbedConfig);
  const [isDeploying, setIsDeploying] = useState<boolean>(false);
  const [isGeneratingTraffic, setIsGeneratingTraffic] = useState<boolean>(false);
  const [deploymentStageIndex, setDeploymentStageIndex] = useState<number>(-1);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [deployedSessionId, setDeployedSessionId] = useState<string | null>(null);
  const [testbedStatus, setTestbedStatus] = useState<any>(null);
  const [configModeTab, setConfigModeTab] = useState<'PREDEFINED' | 'TRANSFORMS'>('PREDEFINED');
  const [logs, setLogs] = useState<string[]>([
    '[15:40:02] Testbed environment initialized in virtual network namespace.',
    '[15:40:05] Security framework verified. Gateway services online.',
    '[15:40:08] Post-Quantum & Multi-Key Exchange extensions active.',
  ]);

  const wasDeployingRef = useRef<boolean>(false);

  // Fast background polling during active deployment (800ms) or standby (2500ms)
  useEffect(() => {
    const poll = async () => {
      try {
        const status = await fetchTestbedStatus();
        setTestbedStatus(status);
        if (status?.last_session_id) {
          setActiveSessionId(status.last_session_id);
        }

        // When backend reports active deployment
        if (status?.is_deploying) {
          setIsDeploying(true);
          wasDeployingRef.current = true;
          if (status.current_stage) {
            setDeploymentStageIndex(Math.max(0, status.current_stage - 1));
          }
        } else if (wasDeployingRef.current) {
          // Transitioned from deploying to completed!
          wasDeployingRef.current = false;
          setIsDeploying(false);
          setDeploymentStageIndex(testbedDeploymentStages.length - 1);
          if (status?.last_session_id) {
            setDeployedSessionId(status.last_session_id);
            setSelectedSessionId(status.last_session_id);
          }
          await refreshSessions();
        }

        const backendLogs = await fetchTestbedLogs();
        if (backendLogs && backendLogs.length > 0) {
          setLogs(backendLogs);
        }
      } catch (err) {
        // network or server startup fallback
      }
    };

    poll();
    const interval = setInterval(poll, isDeploying ? 800 : 2500);
    return () => clearInterval(interval);
  }, [isDeploying, refreshSessions, setSelectedSessionId]);

  // Handle Predefined IKE Proposal Suite Selection (Suites [1] to [11])
  const handleSelectIkeSuite = (suite: PredefinedIkeSuite) => {
    const isPqc = suite.category === 'PQC-HYBRID';
    const isCbc = suite.category === 'CLASSICAL-CBC';
    const isBroken = suite.category === 'BROKEN-INSECURE';

    setConfig((prev) => ({
      ...prev,
      ikeProposalSuite: suite.id,
      encryption: isBroken ? '3DES-CBC' : (isCbc ? 'AES-256' : 'AES-GCM'),
      keyExchangeRounds: suite.rounds,
      pfs: !isBroken,
      dhGroup: isBroken ? '2' : (suite.id === 8 || suite.id === 3 || suite.id === 4 ? '31' : (suite.id === 7 ? '19' : '20')),
      expectedSecurity: isBroken ? 'WEAK' : (isPqc ? 'STRONG' : (isCbc ? 'ACCEPTABLE' : 'STRONG')),
      profileCategory: isBroken ? 'BROKEN / HIGH VULNERABILITY' : (isPqc ? 'POST-QUANTUM HYBRID' : (isCbc ? 'LEGACY CBC' : 'MODERN CLASSICAL')),
    }));

    setLogs((prev) => [
      ...prev,
      `[${new Date().toISOString().split('T')[1].slice(0, 8)}] [IKE SUITE #${suite.id}] Selected: ${suite.label}`,
    ]);
  };

  // Handle Predefined ESP Child SA Suite Selection (Suites [1] to [5])
  const handleSelectEspSuite = (suite: PredefinedEspSuite) => {
    const hasPfs = suite.pfs.includes('PFS') || suite.pfs.includes('Group');
    setConfig((prev) => ({
      ...prev,
      espProposalSuite: suite.id,
      pfs: hasPfs,
    }));

    setLogs((prev) => [
      ...prev,
      `[${new Date().toISOString().split('T')[1].slice(0, 8)}] [ESP SUITE #${suite.id}] Selected: ${suite.label}`,
    ]);
  };

  // Handle Deployment Action
  const handleCreateTestbed = async () => {
    setIsDeploying(true);
    wasDeployingRef.current = true;
    setDeploymentStageIndex(0);
    setDeployedSessionId(null);
    const ts = new Date().toISOString().split('T')[1].slice(0, 8);
    const currentIkeSuite = predefinedIkeSuites.find((s) => s.id === config.ikeProposalSuite);
    const ikeName = currentIkeSuite ? `Suite #${currentIkeSuite.id} (${currentIkeSuite.category})` : config.encryption;

    setLogs((prev) => [
      ...prev,
      `[${ts}] [DEPLOY] Dispatching testbed orchestration for ${ikeName} with ${config.childSaCount || 1} Child SA(s) (${config.mode} mode)...`,
    ]);

    try {
      const res = await deployTestbed(config);
      if (res.sessionIdentifier) {
        setActiveSessionId(res.sessionIdentifier);
      }
      const updated = await fetchTestbedLogs();
      if (updated && updated.length > 0) {
        setLogs(updated);
      }
    } catch (err) {
      setLogs((prev) => [...prev, `[${ts}] [ERROR] Orchestrator deployment failed: ${err}`]);
      setIsDeploying(false);
      wasDeployingRef.current = false;
    }
  };

  // Handle Traffic Injection
  const handleGenerateTraffic = async () => {
    if (isDeploying || isGeneratingTraffic) return;
    setIsGeneratingTraffic(true);
    const ts = new Date().toISOString().split('T')[1].slice(0, 8);
    setLogs((prev) => [
      ...prev,
      `[${ts}] [TRAFFIC] Dispatching synthetic ${config.trafficType} transmission through ${config.childSaCount || 1} Child SA(s)...`,
    ]);
    try {
      await triggerTestbedTraffic(config.trafficType);
      const updated = await fetchTestbedLogs();
      if (updated && updated.length > 0) {
        setLogs(updated);
      }
    } catch (e) {
      setLogs((prev) => [...prev, `[${ts}] [ERROR] Traffic injection failed: ${e}`]);
    } finally {
      setTimeout(() => setIsGeneratingTraffic(false), 1800);
    }
  };

  // Derive active selections for visualizer
  const currentIkeSuite = predefinedIkeSuites.find((s) => s.id === (config.ikeProposalSuite || 1)) || predefinedIkeSuites[0];
  const currentEspSuite = predefinedEspSuites.find((s) => s.id === (config.espProposalSuite || 1)) || predefinedEspSuites[0];
  const rounds = config.keyExchangeRounds || currentIkeSuite.rounds || 1;
  const childSaCount = config.childSaCount || 1;

  const calculateProfile = () => {
    if (currentIkeSuite.category === 'BROKEN-INSECURE') {
      return {
        category: 'INSECURE / DEPRECATED CRYPTOGRAPHY',
        security: 'WEAK' as const,
        score: 32,
        color: 'text-sentinel-critical',
      };
    }
    if (currentIkeSuite.pqc || rounds >= 2) {
      const isTopPqc = currentIkeSuite.additionalKe?.includes('1024') || currentIkeSuite.label?.includes('1024');
      const isKyber768 = currentIkeSuite.additionalKe?.includes('768') || currentIkeSuite.label?.includes('768');
      return {
        category: 'POST-QUANTUM HYBRID',
        security: 'STRONG' as const,
        score: isTopPqc ? 96 : isKyber768 ? 94 : 92,
        color: 'text-sentinel-mint',
      };
    }
    if (currentIkeSuite.category === 'CLASSICAL-CBC' || !config.pfs) {
      return {
        category: 'LEGACY TRANSITIONAL',
        security: 'ACCEPTABLE' as const,
        score: 74,
        color: 'text-sentinel-warning',
      };
    }
    const isTopClassical = currentIkeSuite.encr?.includes('256') || currentIkeSuite.primaryKe?.includes('384');
    return {
      category: 'MODERN CLASSICAL',
      security: 'STRONG' as const,
      score: isTopClassical ? 85 : 82,
      color: 'text-sentinel-copper',
    };
  };

  const currentProfile = calculateProfile();

  return (
    <AppShell hideSidebar={true}>
      <div className="space-y-6 max-w-[1600px] mx-auto pb-10">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-sentinel-border">
          <div>
            <div className="flex items-center gap-2.5">
              <Cpu className="w-5 h-5 text-sentinel-copper" />
              <h1 className="font-mono-tech text-base md:text-lg font-bold tracking-wider text-sentinel-text uppercase">
                IPsec Testbed & Dataset Generator
              </h1>
            </div>
            <p className="text-xs text-sentinel-muted mt-1">
              Automated virtual laboratory for testing cryptographic algorithms, post-quantum key exchanges, and multi-channel traffic security.
            </p>
          </div>
        </div>

        {/* 2-Column Laboratory Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* LEFT: Configuration Controls (7 Cols) */}
          <div className="lg:col-span-7 space-y-5">
            {/* View Mode Switcher */}
            <div className="panel-technical p-1.5 rounded-lg flex items-center justify-between gap-2 border border-sentinel-border bg-sentinel-surface">
              <div className="flex items-center gap-2 w-full">
                <button
                  type="button"
                  onClick={() => setConfigModeTab('PREDEFINED')}
                  className={`flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-md font-mono-tech text-xs transition-all ${
                    configModeTab === 'PREDEFINED'
                      ? 'bg-sentinel-copper text-sentinel-bg font-bold shadow-md'
                      : 'text-sentinel-muted hover:text-sentinel-text hover:bg-sentinel-secondary/60'
                  }`}
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  Standard Security Profiles
                </button>
                <button
                  type="button"
                  onClick={() => setConfigModeTab('TRANSFORMS')}
                  className={`flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-md font-mono-tech text-xs transition-all ${
                    configModeTab === 'TRANSFORMS'
                      ? 'bg-sentinel-copper text-sentinel-bg font-bold shadow-md'
                      : 'text-sentinel-muted hover:text-sentinel-text hover:bg-sentinel-secondary/60'
                  }`}
                >
                  <Sliders className="w-3.5 h-3.5" />
                  Advanced Custom Builder
                </button>
              </div>
            </div>

            {/* TAB 1: PREDEFINED PROPOSAL SUITES */}
            {configModeTab === 'PREDEFINED' && (
              <motion.div
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                className="panel-technical p-5 rounded-lg space-y-4 border border-sentinel-border"
              >
                <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-sentinel-copper" />
                    <span className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                      Key Exchange & Handshake Profile
                    </span>
                  </div>
                  <span className="text-[10px] font-mono-tech px-2.5 py-0.5 rounded bg-sentinel-secondary text-sentinel-copper border border-sentinel-copper/30 font-semibold">
                    11 Curated Profiles
                  </span>
                </div>

                <div className="space-y-2">
                  {predefinedIkeSuites.map((suite) => {
                    const isSelected = (config.ikeProposalSuite || 1) === suite.id;
                    return (
                      <div
                        key={suite.id}
                        onClick={() => handleSelectIkeSuite(suite)}
                        className={`p-2.5 rounded border transition-all cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-2 ${
                          isSelected
                            ? 'bg-sentinel-copper/15 border-sentinel-copper text-sentinel-text shadow-sm'
                            : 'bg-sentinel-secondary/60 border-sentinel-border hover:border-sentinel-copper/50 hover:bg-sentinel-secondary text-sentinel-muted'
                        }`}
                      >
                        <div className="flex items-start sm:items-center gap-2.5">
                          <span
                            className={`font-mono-tech text-xs font-bold px-1.5 py-0.5 rounded ${
                              isSelected
                                ? 'bg-sentinel-copper text-sentinel-bg'
                                : 'bg-sentinel-elevated text-sentinel-muted border border-sentinel-border'
                            }`}
                          >
                            [{suite.id.toString().padStart(2, ' ')}]
                          </span>
                          <div>
                            <div className="font-mono-tech text-xs font-semibold text-sentinel-text flex items-center gap-2">
                              {suite.label}
                            </div>
                            <div className="text-[10px] font-mono-tech text-sentinel-muted/80 mt-0.5">
                              KE1: <span className="text-sentinel-text">{suite.primaryKe}</span>
                              {suite.additionalKe !== 'None' && (
                                <>
                                  {' | '}Quantum-Safe KE: <span className="text-sentinel-mint font-semibold">{suite.additionalKe}</span>
                                </>
                              )}
                            </div>
                          </div>
                        </div>

                        <div className="flex items-center gap-2 self-end sm:self-center">
                          <span
                            className={`text-[9px] font-mono-tech px-2 py-0.5 rounded uppercase font-bold ${
                              suite.category === 'BROKEN-INSECURE'
                                ? 'bg-sentinel-critical/20 text-sentinel-critical border border-sentinel-critical/40'
                                : suite.category === 'PQC-HYBRID'
                                ? 'bg-sentinel-mint/20 text-sentinel-mint border border-sentinel-mint/30'
                                : suite.category === 'CLASSICAL'
                                ? 'bg-sentinel-copper/20 text-sentinel-copper border border-sentinel-copper/30'
                                : 'bg-sentinel-warning/20 text-sentinel-warning border border-sentinel-warning/30'
                            }`}
                          >
                            {suite.category === 'BROKEN-INSECURE' ? 'INSECURE / DEPRECATED' : suite.category === 'PQC-HYBRID' ? 'POST-QUANTUM' : suite.category}
                          </span>
                          {isSelected && <CheckCircle2 className="w-4 h-4 text-sentinel-copper flex-shrink-0" />}
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Predefined Child SA ESP Suites */}
                <div className="pt-4 border-t border-sentinel-border space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text flex items-center gap-2">
                      <Lock className="w-3.5 h-3.5 text-sentinel-mint" />
                      Data Traffic Encryption Profile
                    </span>
                    <span className="text-[10px] font-mono-tech text-sentinel-muted">
                      Data Plane Protection
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {predefinedEspSuites.map((suite) => {
                      const isSelected = (config.espProposalSuite || 1) === suite.id;
                      return (
                        <div
                          key={suite.id}
                          onClick={() => handleSelectEspSuite(suite)}
                          className={`p-2.5 rounded border transition-all cursor-pointer ${
                            isSelected
                              ? 'bg-sentinel-mint/15 border-sentinel-mint text-sentinel-text shadow-sm'
                              : 'bg-sentinel-secondary/60 border-sentinel-border hover:border-sentinel-mint/50 hover:bg-sentinel-secondary text-sentinel-muted'
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-mono-tech text-xs font-bold text-sentinel-text">
                              {suite.label}
                            </span>
                            {isSelected && <CheckCircle2 className="w-3.5 h-3.5 text-sentinel-mint" />}
                          </div>
                          <div className="text-[10px] font-mono-tech text-sentinel-muted mt-1">
                            PFS: <span className="text-sentinel-text">{suite.pfs}</span> | ESN: {suite.esn}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </motion.div>
            )}

            {/* TAB 2: CUSTOM TRANSFORM BUILDER */}
            {configModeTab === 'TRANSFORMS' && (
              <motion.div
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                className="panel-technical p-5 rounded-lg space-y-5 border border-sentinel-border"
              >
                {/* Number of Key Exchanges Selection */}
                <div className="space-y-2 pb-3 border-b border-sentinel-border">
                  <div className="flex items-center justify-between">
                    <label className="text-[11px] font-mono-tech uppercase font-bold text-sentinel-text flex items-center gap-1.5">
                      <KeyRound className="w-3.5 h-3.5 text-sentinel-copper" />
                      Number of Key Exchanges (Multi-Key Exchange)
                    </label>
                    <span className="text-[10px] font-mono-tech text-sentinel-muted">
                      Rounds: {rounds}
                    </span>
                  </div>

                  <div className="grid grid-cols-3 gap-2">
                    {[1, 2, 3].map((r) => (
                      <button
                        key={r}
                        type="button"
                        onClick={() => setConfig({ ...config, keyExchangeRounds: r })}
                        className={`p-2 font-mono-tech text-xs rounded border text-center transition-all ${
                          rounds === r
                            ? 'border-sentinel-copper bg-sentinel-copper/15 text-sentinel-copper font-bold shadow-sm'
                            : 'border-sentinel-border bg-sentinel-secondary text-sentinel-muted hover:text-sentinel-text'
                        }`}
                      >
                        {r === 1 ? '1 KE (Single / Classical)' : r === 2 ? '2 KEs (RFC 9370 Hybrid)' : '3 KEs (Triple Hybrid)'}
                      </button>
                    ))}
                  </div>

                  {/* Dynamic KE Dropdowns */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
                    {/* Primary KE */}
                    <div className="space-y-1">
                      <label className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                        Primary Key Exchange Group (KE1)
                      </label>
                      <select
                        value={config.primaryKeyExchange || '20'}
                        onChange={(e) =>
                          setConfig({
                            ...config,
                            primaryKeyExchange: e.target.value,
                            saInitTransforms: { ...config.saInitTransforms, ke: e.target.value },
                          })
                        }
                        className="w-full p-2 bg-sentinel-secondary border border-sentinel-border rounded font-mono-tech text-xs text-sentinel-text focus:outline-none focus:border-sentinel-copper"
                      >
                        {ikev2KeyExchangeTransforms.map((ke) => (
                          <option key={ke.id} value={ke.id}>
                            [{ke.id}] {ke.name}
                          </option>
                        ))}
                      </select>
                    </div>

                    {/* Additional KE 1 (RFC 9370) */}
                    {rounds >= 2 && (
                      <div className="space-y-1">
                        <label className="text-[10px] font-mono-tech uppercase text-sentinel-mint font-semibold">
                          Additional Key Exchange 1 (KE2 - Post-Quantum)
                        </label>
                        <select
                          value={config.additionalKeyExchange1 || '36'}
                          onChange={(e) => setConfig({ ...config, additionalKeyExchange1: e.target.value })}
                          className="w-full p-2 bg-sentinel-secondary border border-sentinel-mint/40 rounded font-mono-tech text-xs text-sentinel-text focus:outline-none focus:border-sentinel-mint"
                        >
                          {ikev2KeyExchangeTransforms
                            .filter((ke) => ke.type === 'PQC')
                            .map((ke) => (
                              <option key={ke.id} value={ke.id}>
                                [{ke.id}] {ke.name}
                              </option>
                            ))}
                        </select>
                      </div>
                    )}

                    {/* Additional KE 2 (Triple-Hybrid) */}
                    {rounds >= 3 && (
                      <div className="space-y-1 sm:col-span-2">
                        <label className="text-[10px] font-mono-tech uppercase text-sentinel-copper font-semibold">
                          Additional Key Exchange 2 (KE3 - Secondary PQC / KEM)
                        </label>
                        <select
                          value={config.additionalKeyExchange2 || '39'}
                          onChange={(e) => setConfig({ ...config, additionalKeyExchange2: e.target.value })}
                          className="w-full p-2 bg-sentinel-secondary border border-sentinel-copper/40 rounded font-mono-tech text-xs text-sentinel-text focus:outline-none focus:border-sentinel-copper"
                        >
                          {ikev2KeyExchangeTransforms.map((ke) => (
                            <option key={ke.id} value={ke.id}>
                              [{ke.id}] {ke.name}
                            </option>
                          ))}
                        </select>
                      </div>
                    )}
                  </div>
                </div>

                {/* Granular IKE SA INIT Transform Dropdowns */}
                <div className="space-y-3 pb-3 border-b border-sentinel-border">
                  <span className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text flex items-center gap-1.5">
                    <ShieldCheck className="w-3.5 h-3.5 text-sentinel-copper" />
                    IKE SA INIT Transforms (IANA IKEv2 Registry)
                  </span>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {/* Transform 1: Encryption */}
                    <div className="space-y-1">
                      <label className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                        Transform 1: Encryption Algorithm (ENCR)
                      </label>
                      <select
                        value={config.saInitTransforms?.encr || '20'}
                        onChange={(e) =>
                          setConfig({
                            ...config,
                            saInitTransforms: { ...config.saInitTransforms, encr: e.target.value },
                          })
                        }
                        className="w-full p-2 bg-sentinel-secondary border border-sentinel-border rounded font-mono-tech text-xs text-sentinel-text focus:outline-none focus:border-sentinel-copper"
                      >
                        {ikev2EncryptionTransforms.map((item) => (
                          <option key={item.id} value={item.id}>
                            [{item.id}] {item.name}
                          </option>
                        ))}
                      </select>
                    </div>

                    {/* Transform 2: PRF */}
                    <div className="space-y-1">
                      <label className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                        Transform 2: Pseudo-random Function (PRF)
                      </label>
                      <select
                        value={config.saInitTransforms?.prf || '6'}
                        onChange={(e) =>
                          setConfig({
                            ...config,
                            saInitTransforms: { ...config.saInitTransforms, prf: e.target.value },
                          })
                        }
                        className="w-full p-2 bg-sentinel-secondary border border-sentinel-border rounded font-mono-tech text-xs text-sentinel-text focus:outline-none focus:border-sentinel-copper"
                      >
                        {ikev2PrfTransforms.map((item) => (
                          <option key={item.id} value={item.id}>
                            [{item.id}] {item.name}
                          </option>
                        ))}
                      </select>
                    </div>

                    {/* Transform 3: Integrity */}
                    <div className="space-y-1">
                      <label className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                        Transform 3: Integrity Algorithm (INTEG)
                      </label>
                      <select
                        value={config.saInitTransforms?.integ || '0'}
                        onChange={(e) =>
                          setConfig({
                            ...config,
                            saInitTransforms: { ...config.saInitTransforms, integ: e.target.value },
                          })
                        }
                        className="w-full p-2 bg-sentinel-secondary border border-sentinel-border rounded font-mono-tech text-xs text-sentinel-text focus:outline-none focus:border-sentinel-copper"
                      >
                        {ikev2IntegrityTransforms.map((item) => (
                          <option key={item.id} value={item.id}>
                            [{item.id}] {item.name}
                          </option>
                        ))}
                      </select>
                    </div>

                    {/* Transform 4: Key Exchange Method (Bound to KE1) */}
                    <div className="space-y-1">
                      <label className="text-[10px] font-mono-tech uppercase text-sentinel-muted flex items-center justify-between">
                        <span>Transform 4: Key Exchange (KE)</span>
                        <span className="text-[9px] text-sentinel-mint font-semibold">Synced with KE1</span>
                      </label>
                      <div className="p-2 bg-sentinel-secondary/70 border border-sentinel-border rounded font-mono-tech text-xs text-sentinel-text flex items-center justify-between">
                        <span className="truncate">
                          {ikev2KeyExchangeTransforms.find(k => k.id === (config.primaryKeyExchange || '20'))?.name || 'Group 20: 384-bit Random ECP (NIST P-384)'}
                        </span>
                        <span className="text-[10px] font-bold text-sentinel-copper flex-shrink-0 ml-2">
                          [KE1]
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Granular Child SA Transforms */}
                <div className="space-y-3">
                  <span className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-sentinel-mint" />
                    Child SA Proposals & Transforms (ESP Protocol)
                  </span>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {/* Child Transform 1: ENCR */}
                    <div className="space-y-1">
                      <label className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                        Child Transform 1: ESP Encryption (ENCR)
                      </label>
                      <select
                        value={config.childSaTransforms?.encr || '20'}
                        onChange={(e) =>
                          setConfig({
                            ...config,
                            childSaTransforms: { ...config.childSaTransforms, encr: e.target.value },
                          })
                        }
                        className="w-full p-2 bg-sentinel-secondary border border-sentinel-border rounded font-mono-tech text-xs text-sentinel-text focus:outline-none focus:border-sentinel-copper"
                      >
                        {ikev2EncryptionTransforms.map((item) => (
                          <option key={item.id} value={item.id}>
                            [{item.id}] {item.name}
                          </option>
                        ))}
                      </select>
                    </div>

                    {/* Child Transform 3: INTEG */}
                    <div className="space-y-1">
                      <label className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                        Child Transform 3: Integrity (INTEG)
                      </label>
                      <select
                        value={config.childSaTransforms?.integ || '0'}
                        onChange={(e) =>
                          setConfig({
                            ...config,
                            childSaTransforms: { ...config.childSaTransforms, integ: e.target.value },
                          })
                        }
                        className="w-full p-2 bg-sentinel-secondary border border-sentinel-border rounded font-mono-tech text-xs text-sentinel-text focus:outline-none focus:border-sentinel-copper"
                      >
                        {ikev2IntegrityTransforms.map((item) => (
                          <option key={item.id} value={item.id}>
                            [{item.id}] {item.name}
                          </option>
                        ))}
                      </select>
                    </div>

                    {/* Child Transform 4: DH/PFS */}
                    <div className="space-y-1">
                      <label className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                        Child Transform 4: Forward Secrecy Rekey DH Group (PFS)
                      </label>
                      <select
                        value={config.childSaTransforms?.dh || '20'}
                        onChange={(e) =>
                          setConfig({
                            ...config,
                            childSaTransforms: { ...config.childSaTransforms, dh: e.target.value },
                          })
                        }
                        className="w-full p-2 bg-sentinel-secondary border border-sentinel-border rounded font-mono-tech text-xs text-sentinel-text focus:outline-none focus:border-sentinel-copper"
                      >
                        <option value="0">[0] None (No PFS Rekeying)</option>
                        {ikev2KeyExchangeTransforms.map((item) => (
                          <option key={item.id} value={item.id}>
                            [{item.id}] {item.name}
                          </option>
                        ))}
                      </select>
                    </div>

                    {/* Child Transform 5: ESN */}
                    <div className="space-y-1">
                      <label className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                        Child Transform 5: Extended Sequence Numbers (ESN)
                      </label>
                      <select
                        value={config.childSaTransforms?.esn || '1'}
                        onChange={(e) =>
                          setConfig({
                            ...config,
                            childSaTransforms: { ...config.childSaTransforms, esn: e.target.value },
                          })
                        }
                        className="w-full p-2 bg-sentinel-secondary border border-sentinel-border rounded font-mono-tech text-xs text-sentinel-text focus:outline-none focus:border-sentinel-copper"
                      >
                        {ikev2EsnTransforms.map((item) => (
                          <option key={item.id} value={item.id}>
                            [{item.id}] {item.name}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>
                </div>
              </motion.div>
            )}

            {/* SECTION: TUNNEL & NETWORK SETTINGS */}
            <div className="panel-technical p-5 rounded-lg space-y-4 border border-sentinel-border">
              <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
                <span className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text flex items-center gap-2">
                  <Network className="w-4 h-4 text-sentinel-copper" />
                  Tunnel & Network Settings
                </span>
                <span className="text-[10px] font-mono-tech text-sentinel-muted">
                  Deployment Configuration
                </span>
              </div>

              {/* Number of Child SAs / Data Tunnels (Only shown in Custom Transform Builder mode) */}
              {configModeTab === 'TRANSFORMS' && (
                <div className="space-y-2 pb-3 border-b border-sentinel-border/60">
                  <label className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                    Data Channels (Data Plane Tunnels)
                  </label>
                  <div className="grid grid-cols-3 gap-2">
                    {[1, 2, 3].map((count) => (
                      <button
                        key={count}
                        type="button"
                        onClick={() => setConfig({ ...config, childSaCount: count })}
                        className={`p-2 font-mono-tech text-xs rounded border text-center transition-all ${
                          childSaCount === count
                            ? 'border-sentinel-copper bg-sentinel-copper/15 text-sentinel-copper font-bold shadow-sm'
                            : 'border-sentinel-border bg-sentinel-secondary text-sentinel-muted hover:text-sentinel-text'
                        }`}
                      >
                        {count === 1 ? '1 Data Channel' : `${count} Data Channels`}
                      </button>
                    ))}
                  </div>

                  {/* Channel Breakdown */}
                  <div className="space-y-1.5 pt-1">
                    <div className="p-2 rounded bg-sentinel-secondary/60 border border-sentinel-border/70 flex items-center justify-between font-mono-tech text-xs">
                      <div className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-sentinel-mint" />
                        <span className="font-semibold text-sentinel-text">Channel 1: Corporate Traffic</span>
                      </div>
                      <span className="text-[10px] text-sentinel-muted">172.28.0.2/32 ↔ 172.28.0.3/32 (All Protocols)</span>
                    </div>

                    {childSaCount >= 2 && (
                      <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        className="p-2 rounded bg-sentinel-secondary/60 border border-sentinel-border/70 flex items-center justify-between font-mono-tech text-xs"
                      >
                        <div className="flex items-center gap-2">
                          <span className="w-2 h-2 rounded-full bg-sentinel-copper" />
                          <span className="font-semibold text-sentinel-text">Channel 2: Voice Traffic (VoIP)</span>
                        </div>
                        <span className="text-[10px] text-sentinel-muted">172.28.0.2/32[udp] ↔ 172.28.0.3/32[udp] (Low Latency)</span>
                      </motion.div>
                    )}

                    {childSaCount >= 3 && (
                      <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        className="p-2 rounded bg-sentinel-secondary/60 border border-sentinel-border/70 flex items-center justify-between font-mono-tech text-xs"
                      >
                        <div className="flex items-center gap-2">
                          <span className="w-2 h-2 rounded-full bg-sentinel-warning" />
                          <span className="font-semibold text-sentinel-text">Channel 3: Management Telemetry</span>
                        </div>
                        <span className="text-[10px] text-sentinel-muted">172.28.0.2/32[icmp] ↔ 172.28.0.3/32[icmp] (Telemetry)</span>
                      </motion.div>
                    )}
                  </div>
                </div>
              )}

              {/* Mode & IP Stack */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
                <div className="space-y-1.5">
                  <label className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                    Encapsulation Mode
                  </label>
                  <div className="grid grid-cols-2 gap-2">
                    {(['Tunnel', 'Transport'] as const).map((m) => (
                      <button
                        key={m}
                        type="button"
                        onClick={() => setConfig({ ...config, mode: m })}
                        className={`p-2.5 font-mono-tech text-xs rounded-md border text-center transition-all ${
                          config.mode === m
                            ? 'border-sentinel-copper bg-sentinel-copper/15 text-sentinel-copper font-bold shadow-sm'
                            : 'border-sentinel-border bg-sentinel-secondary text-sentinel-muted hover:text-sentinel-text'
                        }`}
                      >
                        {m} Mode
                      </button>
                    ))}
                  </div>
                </div>

                <div className="space-y-1.5">
                  <label className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                    IP Stack & Forward Secrecy
                  </label>
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={() =>
                        setConfig({
                          ...config,
                          ipVersion: config.ipVersion === 'IPv4' ? 'IPv6' : 'IPv4',
                        })
                      }
                      className="p-2.5 font-mono-tech text-xs rounded-md border border-sentinel-border bg-sentinel-secondary text-sentinel-text text-center hover:border-sentinel-copper transition-colors"
                    >
                      {config.ipVersion}
                    </button>
                    <button
                      type="button"
                      onClick={() => setConfig({ ...config, pfs: !config.pfs })}
                      className={`p-2.5 font-mono-tech text-xs rounded-md border text-center transition-all ${
                        config.pfs
                          ? 'border-sentinel-mint bg-sentinel-mint/15 text-sentinel-mint font-bold'
                          : 'border-sentinel-border bg-sentinel-secondary text-sentinel-muted'
                      }`}
                    >
                      PFS: {config.pfs ? 'ENABLED' : 'DISABLED'}
                    </button>
                  </div>
                </div>
              </div>

              {/* Traffic Pattern */}
              <div className="pt-2 border-t border-sentinel-border space-y-2">
                <label className="text-[10px] font-mono-tech uppercase text-sentinel-muted">
                  Synthetic In-Tunnel Traffic Profile
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
                  className="flex items-center gap-2 px-4 py-2.5 bg-sentinel-copper text-sentinel-bg font-mono-tech text-xs font-bold rounded hover:bg-sentinel-copperHover transition-all disabled:opacity-60 shadow-sm"
                >
                  {isDeploying ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin text-sentinel-bg" />
                      DEPLOYING TESTBED...
                    </>
                  ) : (
                    <>
                      <Cpu className="w-4 h-4" />
                      PROVISION & DEPLOY TESTBED
                    </>
                  )}
                </button>
                <button
                  disabled={isDeploying || isGeneratingTraffic}
                  onClick={handleGenerateTraffic}
                  className="flex items-center gap-2 px-3.5 py-2.5 bg-sentinel-elevated border border-sentinel-border text-sentinel-text font-mono-tech text-xs rounded hover:border-sentinel-copper transition-colors disabled:opacity-50"
                >
                  {isGeneratingTraffic ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin text-sentinel-mint" />
                      INJECTING TRAFFIC...
                    </>
                  ) : (
                    <>
                      <Send className="w-3.5 h-3.5 text-sentinel-mint" />
                      GENERATE TRAFFIC BURST
                    </>
                  )}
                </button>
                <Link
                  href="/capture"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 px-3.5 py-2.5 bg-sentinel-secondary border border-sentinel-border text-sentinel-muted hover:text-sentinel-text font-mono-tech text-xs rounded transition-colors"
                >
                  <Radio className="w-3.5 h-3.5 text-sentinel-copper" />
                  VIEW PACKET SNIFFER (NEW TAB)
                </Link>
              </div>
            </div>
          </div>

          {/* RIGHT: Live VPN Profile & Deployment Stages (5 Cols) */}
          <div className="lg:col-span-5 space-y-6">
            {/* Live Profile Card */}
            <motion.div
              layout
              className="panel-technical p-5 rounded-lg space-y-4 border-l-4 border-l-sentinel-copper border border-sentinel-border"
            >
              <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-sentinel-copper" />
                  <span className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                    Live VPN Crypto Visualizer
                  </span>
                </div>
                <span className="font-mono-tech text-[10px] px-2 py-0.5 rounded bg-sentinel-copper/15 text-sentinel-copper border border-sentinel-copper/30 font-bold">
                  ACTIVE SPEC
                </span>
              </div>

              <div className="space-y-2.5 font-mono-tech text-xs">
                <div className="flex items-center justify-between py-1 border-b border-sentinel-border/50">
                  <span className="text-sentinel-muted">Selected IKE Suite:</span>
                  <span className="text-sentinel-text font-semibold text-right">
                    Suite #{currentIkeSuite.id} ({currentIkeSuite.category})
                  </span>
                </div>

                <div className="flex items-center justify-between py-1 border-b border-sentinel-border/50">
                  <span className="text-sentinel-muted">Key Exchange Security:</span>
                  <span className="text-sentinel-mint font-semibold">
                    {rounds} Round{rounds > 1 ? 's' : ''} ({rounds === 2 ? 'Dual Hybrid (Classical + PQC)' : rounds === 3 ? 'Triple Hybrid' : 'Classical Standard'})
                  </span>
                </div>

                <div className="flex items-center justify-between py-1 border-b border-sentinel-border/50">
                  <span className="text-sentinel-muted">Primary KE (KE1):</span>
                  <span className="text-sentinel-text">{currentIkeSuite.primaryKe}</span>
                </div>

                {rounds >= 2 && (
                  <div className="flex items-center justify-between py-1 border-b border-sentinel-border/50">
                    <span className="text-sentinel-mint">Additional KE (KE2):</span>
                    <span className="text-sentinel-mint font-bold">{currentIkeSuite.additionalKe}</span>
                  </div>
                )}

                <div className="flex items-center justify-between py-1 border-b border-sentinel-border/50">
                  <span className="text-sentinel-muted">Data Tunnels:</span>
                  <span className="text-sentinel-copper font-semibold">{childSaCount} Encrypted Channel{childSaCount > 1 ? 's' : ''}</span>
                </div>

                <div className="flex items-center justify-between py-1 border-b border-sentinel-border/50">
                  <span className="text-sentinel-muted">Data Encryption:</span>
                  <span className="text-sentinel-text">{currentEspSuite.label}</span>
                </div>

                <div className="flex items-center justify-between py-1 border-b border-sentinel-border/50">
                  <span className="text-sentinel-muted">Encapsulation / PFS:</span>
                  <span className="text-sentinel-text">
                    {config.mode} Mode | PFS: {config.pfs ? 'YES' : 'NO'}
                  </span>
                </div>

                <div className="flex items-center justify-between py-1 border-b border-sentinel-border/50">
                  <span className="text-sentinel-muted">Security Profile:</span>
                  <span className={`font-bold ${currentProfile.color}`}>
                    {currentProfile.category}
                  </span>
                </div>

                <div className="flex items-center justify-between pt-1">
                  <span className="text-sentinel-muted">Expected Security Score:</span>
                  <span className="px-2 py-0.5 rounded bg-sentinel-secondary text-sentinel-mint border border-sentinel-mint/30 font-bold">
                    {currentProfile.security} ({currentProfile.score}/100)
                  </span>
                </div>
              </div>
            </motion.div>

            {/* Deployment Progression Pipeline */}
            <div className="panel-technical p-5 rounded-lg space-y-3 border border-sentinel-border">
              <div className="flex items-center justify-between pb-2 border-b border-sentinel-border">
                <span className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                  Deployment Progression
                </span>
                {isDeploying ? (
                  <span className="font-mono-tech text-[10px] text-sentinel-copper animate-pulse">
                    PROVISIONING...
                  </span>
                ) : deployedSessionId ? (
                  <span className="font-mono-tech text-[10px] text-sentinel-mint font-bold">
                    NEW: {deployedSessionId}
                  </span>
                ) : activeSessionId ? (
                  <span className="font-mono-tech text-[10px] text-sentinel-muted">
                    ACTIVE: {activeSessionId}
                  </span>
                ) : null}
              </div>

              {/* Newly Created Session Action Card */}
              {deployedSessionId && !isDeploying && (
                <motion.div
                  initial={{ opacity: 0, y: -6 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="p-3.5 rounded border border-sentinel-mint/40 bg-sentinel-mint/10 space-y-2.5 font-mono-tech"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 text-sentinel-mint" />
                      <span className="text-xs font-bold text-sentinel-text uppercase">
                        New Session Established: {deployedSessionId}
                      </span>
                    </div>
                    <span className="px-2 py-0.5 rounded bg-sentinel-mint/20 text-sentinel-mint text-[10px] font-bold">
                      {childSaCount} ACTIVE TUNNEL{childSaCount > 1 ? 'S' : ''}
                    </span>
                  </div>
                  <p className="text-[11px] text-sentinel-muted leading-relaxed">
                    Secure tunnels established, network traffic telemetry recorded, and security posture verified.
                  </p>
                  <div className="flex flex-wrap items-center gap-2 pt-1">
                    <Link
                      href={`/sessions/${deployedSessionId}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-3 py-1.5 rounded bg-sentinel-mint text-sentinel-surface text-xs font-bold flex items-center gap-1.5 hover:bg-sentinel-mint/90 transition-all"
                    >
                      Inspect Session
                      <ArrowUpRight className="w-3.5 h-3.5" />
                    </Link>
                    <Link
                      href="/capture"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-3 py-1.5 rounded border border-sentinel-border hover:border-sentinel-copper text-sentinel-text text-xs flex items-center gap-1.5 transition-all bg-sentinel-secondary"
                    >
                      Packet Stream
                    </Link>
                  </div>
                </motion.div>
              )}

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

        {/* Bottom: Activity Console Output */}
        <div className="panel-technical p-4 rounded-lg space-y-2 bg-sentinel-elevated/70 border border-sentinel-border">
          <div className="flex items-center justify-between pb-2 border-b border-sentinel-border/50 text-xs font-mono-tech text-sentinel-muted">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-sentinel-copper" />
              <span className="text-sentinel-text uppercase font-semibold">
                Testbed Activity Console
              </span>
            </div>
            <span className="text-sentinel-mint">Gateway Engine Online</span>
          </div>

          <div className="h-32 overflow-y-auto space-y-1 font-mono-tech text-[11px] text-sentinel-muted p-1">
            {logs.map((log, index) => (
              <div key={index} className="leading-relaxed">
                <span className="text-sentinel-copper mr-2">$</span>
                <span
                  className={
                    log.includes('[ERROR]') || log.includes('failed') || log.includes('Error')
                      ? 'text-sentinel-critical font-semibold'
                      : log.includes('[!]') || log.includes('Warning')
                      ? 'text-sentinel-warning'
                      : log.includes('[ONLINE]') || log.includes('[+]') || log.includes('complete')
                      ? 'text-sentinel-mint font-semibold'
                      : 'text-sentinel-text'
                  }
                >
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
