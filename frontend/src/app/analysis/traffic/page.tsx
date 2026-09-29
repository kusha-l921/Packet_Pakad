'use client';

import React, { useState, useEffect } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import { AnalysisTabs } from '@/components/analysis/AnalysisTabs';
import { fetchTrafficClassification } from '@/lib/api/analysis';
import { fetchTestbedStatus } from '@/lib/api/testbed';
import { ProgressBar } from '@/components/common/TechnicalField';
import { StatusBadge } from '@/components/common/StatusBadge';
import { NoDataState } from '@/components/common/NoDataState';
import { SessionSelector } from '@/components/common/SessionSelector';
import { useSession } from '@/context/SessionContext';
import { TrafficClassification } from '@/types';
import { motion } from 'framer-motion';
import { mockTrafficClassification, mockLivePackets, mockAnomalyResult, mockMetadataExposure } from '@/data/traffic';
import { LiveWirePacket } from '@/types';
import {
  Activity,
  AlertTriangle,
  EyeOff,
  BarChart3,
  Cpu,
  Layers,
  ArrowRight,
  ShieldCheck,
  CheckCircle2,
  RefreshCw,
  Shield,
  Filter,
  Package,
  Sparkles,
  Info,
  Radio,
  Zap,
} from 'lucide-react';

export default function TrafficIntelligencePage() {
  const { selectedSessionId, selectedSession } = useSession();
  const [trafficData, setTrafficData] = useState<TrafficClassification>(mockTrafficClassification);
  const [testbedStatus, setTestbedStatus] = useState<any>(null);

  // Wire Packets & Graph State
  const [packetFilter, setPacketFilter] = useState<'ALL' | 'TFC' | 'BURST' | 'NOMINAL'>('ALL');
  const [graphMode, setGraphMode] = useState<'PACKETS' | 'BURST' | 'COMBINED'>('PACKETS');
  const [tfcDefenseActive, setTfcDefenseActive] = useState<boolean>(true);
  const [selectedPacket, setSelectedPacket] = useState<LiveWirePacket | null>(mockLivePackets[2]);

  const activeAnomaly = {
    score: tfcDefenseActive ? 0.18 : 0.44,
    threshold: 0.72,
    status: (tfcDefenseActive ? 'NORMAL' : 'NORMAL') as 'NORMAL' | 'ANOMALOUS',
    models: {
      autoencoder: tfcDefenseActive ? 0.16 : 0.38,
      isolationForest: tfcDefenseActive ? 0.20 : 0.49,
    },
    explanation: tfcDefenseActive
      ? 'Traffic cadence with active Traffic Flow Confidentiality (TFC) padding equalizes inter-arrival burst entropy. ML classifiers fail to infer cleartext video frame boundaries.'
      : 'Traffic cadence matches unpadded video burst distribution. Periodic 33.3ms bursts expose teleconference frame rate to eavesdroppers.',
  };

  useEffect(() => {
    fetchTestbedStatus()
      .then(setTestbedStatus)
      .catch(() => {});

    fetchTrafficClassification(selectedSessionId || undefined)
      .then((data) => {
        if (data && data.metrics && data.primaryClass !== 'STANDBY' && Array.isArray(data.timelineData) && data.timelineData.length > 0) {
          const packetsList = (data.packets && data.packets.length > 0) ? data.packets : mockLivePackets;
          setTrafficData({
            ...data,
            packets: packetsList,
          });
        } else {
          setTrafficData(mockTrafficClassification);
        }
      })
      .catch(() => {
        setTrafficData(mockTrafficClassification);
      });
  }, [selectedSessionId]);

  // Derive active packets based on TFC defense toggle and packet filter
  const rawPackets = trafficData.packets && trafficData.packets.length > 0
    ? trafficData.packets
    : mockLivePackets;

  const currentPackets = rawPackets.filter((p) => {
    if (!tfcDefenseActive && p.isPadding) return false;
    if (packetFilter === 'TFC') return p.isPadding;
    if (packetFilter === 'BURST') return p.isBurst;
    if (packetFilter === 'NOMINAL') return !p.isPadding && !p.isBurst;
    return true;
  });

  const totalPacketsCount = currentPackets.length;
  const paddingPacketsCount = currentPackets.filter((p) => p.isPadding).length;
  const burstPacketsCount = currentPackets.filter((p) => p.isBurst).length;

  // Recalculate confidence based on synthetic TFC stream padding defense
  const displayConfidence = tfcDefenseActive
    ? Math.round(trafficData.confidence * 0.35)
    : trafficData.confidence;

  const displayPrimaryClass = tfcDefenseActive
    ? 'OBFUSCATED (CONSTANT BITRATE / TFC PADDED)'
    : trafficData.primaryClass;

  return (
    <AppShell>
      <div className="space-y-6 max-w-7xl mx-auto">
        {/* Navigation Tabs for Analysis Section */}
        <AnalysisTabs />

        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-sentinel-border">
          <div>
            <div className="flex items-center gap-2">
              <Activity className="w-5 h-5 text-sentinel-copper" />
              <h1 className="font-mono-tech text-base md:text-lg font-bold tracking-wider text-sentinel-text uppercase">
                Encrypted Traffic Intelligence & Metadata Exposure
              </h1>
            </div>
            <p className="text-xs text-sentinel-muted mt-0.5">
              Side-channel behavioural fingerprinting, statistical burst cadence extraction, and Traffic Flow Confidentiality (TFC) stream padding inspection.
            </p>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <SessionSelector />
          </div>
        </div>

        {/* Section 1: Encrypted Traffic Intelligence & Live Wire Packets Graph */}
        <div className="panel-technical p-5 rounded-lg space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-sentinel-border">
            <div className="flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-sentinel-copper" />
              <div>
                <h2 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                  Encrypted Traffic Timeline & Live Wire Packets Graph
                </h2>
                <p className="text-[10px] font-mono-tech text-sentinel-muted">
                  Discrete packet-by-packet MTU inspection and Traffic Flow Confidentiality (TFC) stream analysis
                </p>
              </div>
            </div>

            {/* View Mode & TFC Stream Padding Controls */}
            <div className="flex items-center gap-2 flex-wrap">
              {/* TFC Defense Toggle */}
              <button
                onClick={() => setTfcDefenseActive(!tfcDefenseActive)}
                className={`flex items-center gap-1.5 px-3 py-1 rounded text-[11px] font-mono-tech font-bold transition-all border ${
                  tfcDefenseActive
                    ? 'bg-purple-950/50 border-purple-600 text-purple-300 shadow-[0_0_12px_rgba(168,85,247,0.25)]'
                    : 'bg-sentinel-secondary/40 border-sentinel-border text-sentinel-muted hover:text-sentinel-text'
                }`}
                title="Toggle Traffic Flow Confidentiality stream padding (RFC 4303 §2.7 TFC Padding)"
              >
                <Sparkles className={`w-3.5 h-3.5 ${tfcDefenseActive ? 'text-purple-400 animate-pulse' : 'text-sentinel-muted'}`} />
                <span>{tfcDefenseActive ? 'TFC Padding Active (RFC 4303)' : 'Enable TFC Padding'}</span>
              </button>

              {/* Graph View Selector */}
              <div className="flex items-center bg-sentinel-secondary/40 rounded p-0.5 border border-sentinel-border font-mono-tech text-[10px]">
                <button
                  onClick={() => setGraphMode('PACKETS')}
                  className={`px-2.5 py-1 rounded transition-colors ${
                    graphMode === 'PACKETS'
                      ? 'bg-sentinel-copper text-white font-bold'
                      : 'text-sentinel-muted hover:text-sentinel-text'
                  }`}
                >
                  Live Wire Stream
                </button>
                <button
                  onClick={() => setGraphMode('BURST')}
                  className={`px-2.5 py-1 rounded transition-colors ${
                    graphMode === 'BURST'
                      ? 'bg-sentinel-copper text-white font-bold'
                      : 'text-sentinel-muted hover:text-sentinel-text'
                  }`}
                >
                  Burst Cadence
                </button>
                <button
                  onClick={() => setGraphMode('COMBINED')}
                  className={`px-2.5 py-1 rounded transition-colors ${
                    graphMode === 'COMBINED'
                      ? 'bg-sentinel-copper text-white font-bold'
                      : 'text-sentinel-muted hover:text-sentinel-text'
                  }`}
                >
                  Combined
                </button>
              </div>
            </div>
          </div>

          {/* Real-time Ticker & Packet Filters */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-[11px] font-mono-tech pb-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sentinel-muted text-[10px] uppercase font-bold">Filter:</span>
              <button
                onClick={() => setPacketFilter('ALL')}
                className={`px-2 py-0.5 rounded text-[10px] border transition-colors ${
                  packetFilter === 'ALL'
                    ? 'bg-sentinel-elevated text-sentinel-text border-sentinel-border font-bold'
                    : 'text-sentinel-muted border-transparent hover:text-sentinel-text'
                }`}
              >
                All ({currentPackets.length})
              </button>
              <button
                onClick={() => setPacketFilter('TFC')}
                className={`px-2 py-0.5 rounded text-[10px] border transition-colors flex items-center gap-1 ${
                  packetFilter === 'TFC'
                    ? 'bg-purple-950/60 text-purple-300 border-purple-700 font-bold'
                    : 'text-purple-400/80 border-transparent hover:text-purple-300'
                }`}
              >
                <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
                TFC Padding ({rawPackets.filter((p) => p.isPadding).length})
              </button>
              <button
                onClick={() => setPacketFilter('BURST')}
                className={`px-2 py-0.5 rounded text-[10px] border transition-colors flex items-center gap-1 ${
                  packetFilter === 'BURST'
                    ? 'bg-amber-950/60 text-amber-300 border-amber-700 font-bold'
                    : 'text-amber-400/80 border-transparent hover:text-amber-300'
                }`}
              >
                <span className="w-1.5 h-1.5 rounded-full bg-sentinel-copper" />
                I-Frames ({rawPackets.filter((p) => p.isBurst).length})
              </button>
              <button
                onClick={() => setPacketFilter('NOMINAL')}
                className={`px-2 py-0.5 rounded text-[10px] border transition-colors flex items-center gap-1 ${
                  packetFilter === 'NOMINAL'
                    ? 'bg-emerald-950/60 text-emerald-300 border-emerald-700 font-bold'
                    : 'text-emerald-400/80 border-transparent hover:text-emerald-300'
                }`}
              >
                <span className="w-1.5 h-1.5 rounded-full bg-sentinel-mint" />
                P-Frames ({rawPackets.filter((p) => !p.isPadding && !p.isBurst).length})
              </button>
            </div>

            {/* Status Indicator */}
            <div className="flex items-center gap-3 text-[10px]">
              <span className="flex items-center gap-1.5 text-sentinel-muted">
                <span className="w-2 h-2 rounded-full bg-purple-500 animate-ping" />
                TFC Stream Padding: <strong className={tfcDefenseActive ? 'text-purple-400' : 'text-rose-400'}>{tfcDefenseActive ? 'ACTIVE' : 'DISABLED'}</strong>
              </span>
              <span className="text-sentinel-muted">
                Observed Inter-Arrival Cadence: <strong className="text-sentinel-text">33.3ms</strong>
              </span>
            </div>
          </div>

          {/* MAIN GRAPH: Live Wire Packets Matrix */}
          {(graphMode === 'PACKETS' || graphMode === 'COMBINED') && (
            <div className="relative p-5 bg-[#080a0f] border border-slate-800 rounded-xl overflow-hidden select-none shadow-2xl">
              {/* Subtle technical background grid */}
              <div
                className="absolute inset-0 pointer-events-none opacity-20"
                style={{
                  backgroundImage: `linear-gradient(rgba(255, 255, 255, 0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(255, 255, 255, 0.05) 1px, transparent 1px)`,
                  backgroundSize: '32px 32px',
                }}
              />

              {/* Y-Axis Label (Packet Size in Bytes) */}
              <div className="absolute left-1.5 top-1/2 -translate-y-1/2 -rotate-90 text-[9px] font-mono-tech uppercase tracking-widest text-slate-400 font-bold z-10">
                ← PACKET SIZE (BYTES) →
              </div>

              {/* Graph Canvas: Height 240px */}
              <div className="relative h-60 ml-8 mr-2 mb-6">
                {/* Horizontal Reference Lines */}
                {/* 1500B MTU Ceiling */}
                <div className="absolute inset-x-0 top-0 border-b border-rose-500/30 flex items-center justify-between text-[9px] font-mono-tech text-rose-400/80 px-2 pointer-events-none">
                  <span>1500B (MTU CEILING)</span>
                  <span className="opacity-50">Wire Boundary</span>
                </div>

                {/* 1420B Video Frame Clumping Threshold */}
                <div className="absolute inset-x-0 top-[12%] border-b border-amber-500/30 border-dashed flex items-center justify-between text-[9px] font-mono-tech text-amber-400/80 px-2 pointer-events-none">
                  <span>1420B (H.264 I-FRAME CLUMPING)</span>
                  <span className="opacity-50">Leakage Profile Threshold</span>
                </div>

                {/* 500B Nominal RTP Threshold */}
                <div className="absolute inset-x-0 top-[65%] border-b border-emerald-500/20 flex items-center justify-between text-[9px] font-mono-tech text-emerald-400/70 px-2 pointer-events-none">
                  <span>500B (NOMINAL DELTA PAYLOAD)</span>
                  <span className="opacity-50">Baseline</span>
                </div>

                {/* Plotted Wire Packets */}
                <div className="absolute inset-0 flex items-end justify-between px-2 pt-6">
                  {currentPackets.map((pkt, idx) => {
                    const yPct = Math.min(94, Math.max(8, Math.round((pkt.size / 1500) * 100)));
                    const isSelected = selectedPacket?.id === pkt.id;

                    return (
                      <div
                        key={pkt.id}
                        className="relative flex flex-col items-center justify-end h-full group"
                        style={{ width: `${100 / Math.max(currentPackets.length, 1)}%` }}
                      >
                        {/* Vertical Stem Line */}
                        <div
                          className={`w-px transition-all ${
                            pkt.isPadding
                              ? 'bg-purple-500/40 group-hover:bg-purple-400'
                              : pkt.isBurst
                              ? 'bg-sentinel-copper/50 group-hover:bg-sentinel-copper'
                              : 'bg-emerald-500/30 group-hover:bg-emerald-400'
                          }`}
                          style={{ height: `${yPct}%` }}
                        />

                        {/* Packet Node Element */}
                        <motion.button
                          whileHover={{ scale: 1.25 }}
                          whileTap={{ scale: 0.95 }}
                          onClick={() => setSelectedPacket(pkt)}
                          className={`absolute rounded-md cursor-pointer transition-all z-20 flex items-center justify-center p-1 text-[9px] font-mono-tech font-bold ${
                            pkt.isPadding
                              ? 'bg-purple-900 text-purple-200 border border-purple-500 shadow-[0_0_10px_rgba(168,85,247,0.4)]'
                              : pkt.isBurst
                              ? 'bg-orange-900 text-orange-200 border border-orange-500 shadow-[0_0_10px_rgba(249,115,22,0.4)]'
                              : 'bg-slate-900 text-emerald-300 border border-emerald-600/70'
                          } ${
                            isSelected
                              ? 'ring-2 ring-white ring-offset-2 ring-offset-[#080a0f] scale-125 z-30'
                              : ''
                          }`}
                          style={{ bottom: `calc(${yPct}% - 10px)` }}
                          title={`Packet #${pkt.seq}: ${pkt.size}B (${pkt.frameType})`}
                        >
                          {pkt.isPadding ? (
                            <span className="flex items-center gap-0.5">
                              <Sparkles className="w-2.5 h-2.5 text-purple-300" />
                              <span className="text-[8px]">TFC</span>
                            </span>
                          ) : (
                            <span className="text-[8px]">{pkt.size >= 1000 ? `${(pkt.size / 1000).toFixed(1)}k` : `${pkt.size}`}</span>
                          )}
                        </motion.button>

                        {/* X-Axis Sequence Tick */}
                        <span className="absolute -bottom-5 text-[8px] font-mono-tech text-slate-500 group-hover:text-slate-300 transition-colors truncate max-w-full">
                          #{pkt.seq % 100}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* X-Axis Label */}
              <div className="text-center ml-8 text-[9px] font-mono-tech uppercase tracking-widest text-slate-400 font-bold">
                ← PACKET ARRIVAL SEQUENCE (TIME INCREMENT ~33.3ms) →
              </div>

              {/* Graph Legend */}
              <div className="flex flex-wrap items-center justify-between gap-3 text-[10px] font-mono-tech text-slate-400 pt-3 border-t border-slate-800/80 mt-4 px-2">
                <div className="flex items-center gap-4 flex-wrap">
                  <span className="flex items-center gap-1.5">
                    <span className="w-3 h-3 rounded bg-purple-900 border border-purple-500 flex items-center justify-center text-[7px] text-purple-200 font-bold">
                      TFC
                    </span>
                    <strong className="text-purple-300">TFC Padding Packet (RFC 4303 §2.7)</strong>
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="w-3 h-3 rounded bg-orange-900 border border-orange-500 flex items-center justify-center text-[7px] text-orange-200 font-bold">
                      B
                    </span>
                    <strong className="text-orange-300">Real H.264 I-Frame Burst (Exposed MTU)</strong>
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="w-3 h-3 rounded bg-slate-900 border border-emerald-600 flex items-center justify-center text-[7px] text-emerald-300 font-bold">
                      P
                    </span>
                    <strong className="text-emerald-300">Real Nominal P-Frame Payload</strong>
                  </span>
                </div>
                <span className="text-slate-500 text-[9px]">Click any packet node to inspect wire dissection dossier</span>
              </div>
            </div>
          )}

          {/* SPARK BAR CADENCE CHART (If BURST or COMBINED Mode) */}
          {(graphMode === 'BURST' || graphMode === 'COMBINED') && (
            <div className="py-4 px-3 bg-sentinel-deep/70 border border-sentinel-border rounded space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-sentinel-border/50 text-[10px] font-mono-tech">
                <span className="text-sentinel-copper font-bold uppercase">
                  Discrete Packet Rate Envelope (Cadence Burst Monitor)
                </span>
                <span className="text-sentinel-muted">Sample Window: 5000ms</span>
              </div>

              <div className="flex items-end justify-between gap-2 h-32 px-2">
                {(trafficData?.timelineData || []).map((item, idx) => {
                  const rateAdjusted = tfcDefenseActive ? Math.max(item.rate, 580) : item.rate;
                  const heightPct = Math.min(100, Math.round((rateAdjusted / 700) * 100));

                  return (
                    <div key={idx} className="flex-1 flex flex-col items-center gap-1.5 group cursor-pointer">
                      <motion.div
                        initial={{ height: 0 }}
                        animate={{ height: `${heightPct}%` }}
                        transition={{ duration: 0.5, delay: idx * 0.03 }}
                        className={`w-full rounded-t transition-colors ${
                          tfcDefenseActive
                            ? 'bg-purple-600/60 hover:bg-purple-500'
                            : item.isBurst
                            ? 'bg-sentinel-copper hover:bg-sentinel-copperHover'
                            : 'bg-sentinel-mint/40 hover:bg-sentinel-mint'
                        }`}
                      />
                      <span className="font-mono-tech text-[9px] text-sentinel-muted opacity-80 group-hover:text-sentinel-copper transition-colors truncate">
                        {item.time}
                      </span>
                    </div>
                  );
                })}
              </div>

              <div className="flex items-center justify-between text-[10px] font-mono-tech text-sentinel-muted pt-2 border-t border-sentinel-border/50 px-2">
                <span className="flex items-center gap-1.5">
                  <span className={`w-2.5 h-2.5 rounded ${tfcDefenseActive ? 'bg-purple-500' : 'bg-sentinel-copper'}`} />
                  {tfcDefenseActive ? 'Equalized Constant Bitrate (TFC Stream Padded)' : 'Periodic Video Frame Burst (H.264 I-Frame)'}
                </span>
                <span className="text-sentinel-mint font-bold">
                  {tfcDefenseActive ? 'Side-Channel Leakage Eliminated' : 'Side-Channel Fingerprint Exposed'}
                </span>
              </div>
            </div>
          )}

          {/* SELECTED PACKET INSPECTOR DRAWER */}
          {selectedPacket && (
            <div className={`p-4 rounded-lg border font-mono-tech text-xs transition-all ${
              selectedPacket.isPadding
                ? 'bg-purple-950/20 border-purple-800/60'
                : selectedPacket.isBurst
                ? 'bg-orange-950/20 border-orange-800/60'
                : 'bg-sentinel-secondary/30 border-sentinel-border'
            }`}>
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2.5 border-b border-sentinel-border/60">
                <div className="flex items-center gap-2">
                  <Package className={`w-4 h-4 ${selectedPacket.isPadding ? 'text-purple-400' : selectedPacket.isBurst ? 'text-sentinel-copper' : 'text-sentinel-mint'}`} />
                  <span className="font-bold text-sentinel-text">
                    PACKET #{selectedPacket.seq} WIRE INSPECTION DOSSIER
                  </span>
                  {selectedPacket.isPadding ? (
                    <span className="px-2 py-0.5 rounded bg-purple-600/30 border border-purple-500 text-purple-300 font-extrabold text-[10px]">
                      TFC PADDING PACKET (RFC 4303 §2.7)
                    </span>
                  ) : (
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      selectedPacket.isBurst
                        ? 'bg-orange-600/30 border border-orange-500 text-orange-300'
                        : 'bg-emerald-600/30 border border-emerald-500 text-emerald-300'
                    }`}>
                      {selectedPacket.frameType}
                    </span>
                  )}
                </div>

                <div className="flex items-center gap-2 text-[10px]">
                  <span className="text-sentinel-muted">TIMESTAMP:</span>
                  <span className="text-sentinel-text font-bold">{selectedPacket.time}</span>
                  <span className="text-sentinel-muted">({selectedPacket.timeOffsetMs}ms offset)</span>
                </div>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-6 gap-3 pt-3">
                <div className="p-2 rounded bg-sentinel-deep/50 border border-sentinel-border">
                  <span className="text-[9px] text-sentinel-muted uppercase block">Protocol</span>
                  <span className="font-bold text-sentinel-text mt-0.5 block">{selectedPacket.protocol}</span>
                </div>

                <div className="p-2 rounded bg-sentinel-deep/50 border border-sentinel-border">
                  <span className="text-[9px] text-sentinel-muted uppercase block">Wire Size</span>
                  <span className={`font-bold mt-0.5 block ${selectedPacket.size >= 1400 ? 'text-sentinel-copper' : 'text-sentinel-text'}`}>
                    {selectedPacket.size} Bytes
                  </span>
                </div>

                <div className="p-2 rounded bg-sentinel-deep/50 border border-sentinel-border">
                  <span className="text-[9px] text-sentinel-muted uppercase block">ESP SPI</span>
                  <span className="font-bold text-sentinel-mint mt-0.5 block">{selectedPacket.spi}</span>
                </div>

                <div className="p-2 rounded bg-sentinel-deep/50 border border-sentinel-border">
                  <span className="text-[9px] text-sentinel-muted uppercase block">Cipher Entropy</span>
                  <span className="font-bold text-sentinel-text mt-0.5 block">{selectedPacket.entropy} bits</span>
                </div>

                <div className="p-2 rounded bg-sentinel-deep/50 border border-sentinel-border">
                  <span className="text-[9px] text-sentinel-muted uppercase block">Direction</span>
                  <span className="font-bold text-sentinel-text mt-0.5 block">{selectedPacket.direction}</span>
                </div>

                <div className="p-2 rounded bg-sentinel-deep/50 border border-sentinel-border">
                  <span className="text-[9px] text-sentinel-muted uppercase block">Exposure Risk</span>
                  <span className={`font-bold mt-0.5 block ${
                    selectedPacket.exposureRisk === 'PROTECTED'
                      ? 'text-purple-400'
                      : selectedPacket.exposureRisk === 'CRITICAL'
                      ? 'text-rose-400'
                      : selectedPacket.exposureRisk === 'HIGH'
                      ? 'text-amber-400'
                      : 'text-emerald-400'
                  }`}>
                    {selectedPacket.exposureRisk}
                  </span>
                </div>
              </div>

              <div className="mt-3 p-2.5 rounded bg-sentinel-deep/70 border border-sentinel-border text-xs leading-relaxed">
                <span className="font-bold text-sentinel-copper mr-1.5">FORENSIC TELEMETRY:</span>
                <span className="text-sentinel-text">{selectedPacket.details}</span>
              </div>
            </div>
          )}

          {/* Metric Strip for Traffic */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 pt-2">
            <div className="p-3 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech">
              <span className="text-[10px] text-sentinel-muted uppercase block">Packet Rate</span>
              <span className="text-xl font-bold text-sentinel-text mt-0.5 block">
                {tfcDefenseActive ? 640 : trafficData.metrics.packetRate} <span className="text-xs text-sentinel-muted font-normal">pkts/s</span>
              </span>
            </div>
            <div className="p-3 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech">
              <span className="text-[10px] text-sentinel-muted uppercase block">Mean Packet Size</span>
              <span className="text-xl font-bold text-sentinel-text mt-0.5 block">
                {tfcDefenseActive ? 1420 : trafficData.metrics.averagePacketSize} <span className="text-xs text-sentinel-muted font-normal">Bytes</span>
              </span>
            </div>
            <div className="p-3 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech">
              <span className="text-[10px] text-sentinel-muted uppercase block">Burst Activity</span>
              <span className={`text-sm font-bold mt-1.5 block ${tfcDefenseActive ? 'text-purple-400' : 'text-sentinel-copper'}`}>
                {tfcDefenseActive ? 'EQUALIZED (TFC)' : trafficData.metrics.burstActivity}
              </span>
            </div>
            <div className="p-3 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech">
              <span className="text-[10px] text-sentinel-muted uppercase block">Directionality</span>
              <span className="text-xs font-bold text-sentinel-mint mt-1.5 block">
                {tfcDefenseActive ? '50% Ingress / 50% Egress' : trafficData.metrics.directionality}
              </span>
            </div>
            <div className="p-3 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech col-span-2 sm:col-span-1">
              <span className="text-[10px] text-sentinel-muted uppercase block">Flow Duration</span>
              <span className="text-xl font-bold text-sentinel-text mt-0.5 block">
                {trafficData.metrics.flowDurationSec}s
              </span>
            </div>
          </div>
        </div>

        {/* Section 2: ML Traffic Classification & Unsupervised Anomaly Detection */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* ML Traffic Classification */}
          <div className="panel-technical p-5 rounded-lg space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-sentinel-copper" />
                <h3 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                  Traffic Classification Inference
                </h3>
              </div>
              <span className={`text-[10px] font-mono-tech ${tfcDefenseActive ? 'text-purple-400' : 'text-sentinel-mint'}`}>
                {displayConfidence}% CONFIDENCE
              </span>
            </div>

            <div className="space-y-4 font-mono-tech">
              <div className={`p-3 rounded border space-y-1 ${
                tfcDefenseActive
                  ? 'bg-purple-950/20 border-purple-800/50'
                  : 'bg-sentinel-secondary/40 border-sentinel-border'
              }`}>
                <span className="text-[10px] text-sentinel-muted uppercase">Primary Inferred Class:</span>
                <div className={`text-sm font-bold ${tfcDefenseActive ? 'text-purple-300' : 'text-sentinel-copper'}`}>
                  {displayPrimaryClass}
                </div>
              </div>

              <div className="space-y-3">
                {trafficData.distribution.map((item) => (
                  <div key={item.label} className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-sentinel-muted">{item.label}</span>
                      <span className="text-sentinel-text font-bold">{item.percentage}%</span>
                    </div>
                    <ProgressBar
                      value={item.percentage}
                      max={100}
                      color={item.percentage > 50 ? 'copper' : 'mint'}
                      height="h-1.5"
                    />
                  </div>
                ))}
              </div>

              <p className="text-[11px] font-sans text-sentinel-muted leading-relaxed pt-2 border-t border-sentinel-border/50">
                Inference derived from packet size entropy, inter-arrival time standard deviation (1.4ms), and directional throughput asymmetry without breaking ESP payload encryption.
              </p>
            </div>
          </div>

          {/* Anomaly Detection */}
          <div className="panel-technical p-5 rounded-lg space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-sentinel-copper" />
                <h3 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                  Multi-Model Anomaly Detection
                </h3>
              </div>
              <StatusBadge status={activeAnomaly.status} size="sm" />
            </div>

            <div className="space-y-4 font-mono-tech">
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 rounded bg-sentinel-secondary/40 border border-sentinel-border">
                  <span className="text-[10px] text-sentinel-muted uppercase block">Anomaly Score</span>
                  <div className={`text-2xl font-bold mt-1 ${activeAnomaly.score >= activeAnomaly.threshold ? 'text-sentinel-critical' : 'text-sentinel-mint'}`}>
                    {activeAnomaly.score.toFixed(2)}
                  </div>
                  <span className="text-[10px] text-sentinel-muted">Threshold: {activeAnomaly.threshold}</span>
                </div>

                <div className="p-3 rounded bg-sentinel-secondary/40 border border-sentinel-border">
                  <span className="text-[10px] text-sentinel-muted uppercase block">Detector Status</span>
                  <div className={`text-lg font-bold mt-1.5 ${activeAnomaly.status === 'ANOMALOUS' ? 'text-sentinel-critical' : 'text-sentinel-mint'}`}>
                    {activeAnomaly.status}
                  </div>
                  <span className="text-[10px] text-sentinel-muted">Evaluated continuous</span>
                </div>
              </div>

              <div className="space-y-2.5 pt-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-sentinel-muted">Autoencoder Reconstruction Loss:</span>
                  <span className="text-sentinel-text font-bold">{activeAnomaly.models.autoencoder}</span>
                </div>
                <ProgressBar
                  value={activeAnomaly.models.autoencoder * 100}
                  max={100}
                  color={activeAnomaly.models.autoencoder > 0.7 ? 'critical' : 'mint'}
                  height="h-1.5"
                />

                <div className="flex items-center justify-between text-xs pt-1">
                  <span className="text-sentinel-muted">Isolation Forest Outlier Score:</span>
                  <span className="text-sentinel-text font-bold">{activeAnomaly.models.isolationForest}</span>
                </div>
                <ProgressBar
                  value={activeAnomaly.models.isolationForest * 100}
                  max={100}
                  color={activeAnomaly.models.isolationForest > 0.7 ? 'critical' : 'mint'}
                  height="h-1.5"
                />
              </div>

              <div className="p-2.5 rounded bg-sentinel-deep border border-sentinel-border text-xs text-sentinel-muted font-sans leading-relaxed">
                {activeAnomaly.explanation}
              </div>
            </div>
          </div>
        </div>

        {/* Section 3: METADATA EXPOSURE ASSESSMENT */}
        <div className="panel-technical p-5 rounded-lg space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
            <div className="flex items-center gap-2">
              <EyeOff className={`w-4 h-4 ${tfcDefenseActive ? 'text-purple-400' : 'text-sentinel-warning'}`} />
              <h3 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                METADATA EXPOSURE ASSESSMENT
              </h3>
            </div>
            <StatusBadge status={tfcDefenseActive ? 'NORMAL' : 'WARNING'} size="sm" />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-3 font-mono-tech text-xs">
              <div className="p-3 rounded bg-sentinel-secondary/30 border border-sentinel-border space-y-2 font-sans">
                <span className="font-mono-tech text-[10px] text-sentinel-copper uppercase font-bold block">
                  Encrypted Payload Behavioral Side-Channels:
                </span>
                <p className="text-sentinel-text text-xs leading-relaxed">
                  {tfcDefenseActive
                    ? 'Traffic Flow Confidentiality padding packets (RFC 4303 §2.7) are actively transmitted on the wire. Packet size entropy and inter-arrival timing jitter effectively mask underlying application stream boundaries.'
                    : 'Traffic cadence exhibits unpadded frame sequences allowing external observers to infer application layer streaming profiles based on packet size distributions.'}
                </p>
              </div>

              <div className="space-y-2 pt-2">
                <div className="flex items-center justify-between p-2 rounded bg-sentinel-secondary/40 border border-sentinel-border">
                  <span className="text-sentinel-muted">Packet-Size Fingerprinting</span>
                  <span className={tfcDefenseActive ? 'text-purple-400 font-bold' : 'text-sentinel-warning font-bold'}>
                    {tfcDefenseActive ? 'SHIELDED (CONSTANT 1420B MTU)' : 'DETECTED (1420B MTU)'}
                  </span>
                </div>
                <div className="flex items-center justify-between p-2 rounded bg-sentinel-secondary/40 border border-sentinel-border">
                  <span className="text-sentinel-muted">Timing Patterns</span>
                  <span className={tfcDefenseActive ? 'text-purple-400 font-bold' : 'text-sentinel-warning font-bold'}>
                    {tfcDefenseActive ? 'MUTED (TFC PADDING STREAM)' : 'DETECTED (33.3ms)'}
                  </span>
                </div>
                <div className="flex items-center justify-between p-2 rounded bg-sentinel-secondary/40 border border-sentinel-border">
                  <span className="text-sentinel-muted">Burst Patterns</span>
                  <span className={tfcDefenseActive ? 'text-purple-400 font-bold' : 'text-sentinel-warning font-bold'}>
                    {tfcDefenseActive ? 'FLATTENED (CADENCE EQUALIZED)' : 'DETECTED (I-Frame)'}
                  </span>
                </div>
                <div className="flex items-center justify-between p-2 rounded bg-sentinel-secondary/40 border border-sentinel-border">
                  <span className="text-sentinel-muted">Directionality Asymmetry</span>
                  <span className="text-sentinel-mint font-bold">
                    {tfcDefenseActive ? '50% EQUALIZED RATIO' : '84% INGRESS'}
                  </span>
                </div>
              </div>
            </div>

            {/* Timeline Observations */}
            <div className="space-y-2 font-mono-tech text-xs">
              <span className="text-[10px] text-sentinel-muted uppercase font-bold block">
                Wire Interception Observations:
              </span>
              <div className="space-y-2">
                {[
                  { event: "ESP Encrypted Flow Verified", leakageType: "Protocol 50 Authentication", time: "Live Wire" },
                  { event: "Packet Cadence Monitoring Active", leakageType: "Timing Distribution", time: "Live Wire" }
                ].map((obs, i) => (
                  <div
                    key={i}
                    className="p-2.5 rounded bg-sentinel-secondary/30 border border-sentinel-border flex items-center justify-between"
                  >
                    <div>
                      <div className="font-bold text-sentinel-text">{obs.event}</div>
                      <div className="text-[10px] text-sentinel-copper">{obs.leakageType}</div>
                    </div>
                    <span className="text-[10px] text-sentinel-muted">{obs.time}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
