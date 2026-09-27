'use client';

import React, { useState } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import {
  mockTrafficClassification,
  mockAnomalyResult,
  mockAnomalousResult,
  mockMetadataExposure,
  mockTrafficTimeline,
} from '@/data/traffic';
import { ProgressBar } from '@/components/common/TechnicalField';
import { StatusBadge } from '@/components/common/StatusBadge';
import { motion } from 'framer-motion';
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
} from 'lucide-react';

export default function TrafficIntelligencePage() {
  const [isAnomalousMode, setIsAnomalousMode] = useState(false);
  const activeAnomaly = isAnomalousMode ? mockAnomalousResult : mockAnomalyResult;

  return (
    <AppShell>
      <div className="space-y-6 max-w-7xl mx-auto">
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
              Side-channel behavioural fingerprinting, statistical burst cadence extraction, and unsupervised anomaly detection.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setIsAnomalousMode(!isAnomalousMode)}
              className={`flex items-center gap-1.5 px-3 py-1.5 font-mono-tech text-xs rounded border transition-colors ${
                isAnomalousMode
                  ? 'bg-sentinel-critical/20 border-sentinel-critical text-sentinel-critical font-bold'
                  : 'bg-sentinel-secondary border-sentinel-border text-sentinel-muted hover:text-sentinel-text'
              }`}
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Toggle Test State: {isAnomalousMode ? 'ANOMALOUS (0.91)' : 'NORMAL (0.18)'}
            </button>
          </div>
        </div>

        {/* Section 1: Encrypted Traffic Timeline & Spark/Burst Visualizer */}
        <div className="panel-technical p-5 rounded-lg space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-sentinel-border">
            <div className="flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-sentinel-copper" />
              <h2 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                Encrypted Traffic Timeline & Temporal Burst Cadence
              </h2>
            </div>
            <span className="text-[10px] font-mono-tech text-sentinel-muted">
              Sample Interval: 5000ms • Discrete Packet Rate (pkts/sec)
            </span>
          </div>

          {/* Spark Bar Chart (TIME → ▁▂▃▂▅▇▆▅▃▂▁▃▅▆▇▅▃▂) */}
          <div className="py-4 px-2 bg-sentinel-deep/70 border border-sentinel-border rounded space-y-3">
            <div className="flex items-end justify-between gap-2 h-36 px-2">
              {mockTrafficTimeline.map((item, idx) => {
                const heightPct = Math.round((item.rate / 700) * 100);
                return (
                  <div key={idx} className="flex-1 flex flex-col items-center gap-1.5 group cursor-pointer">
                    <motion.div
                      initial={{ height: 0 }}
                      animate={{ height: `${heightPct}%` }}
                      transition={{ duration: 0.8, delay: idx * 0.05 }}
                      className={`w-full rounded-t transition-colors ${
                        item.isBurst
                          ? 'bg-sentinel-copper hover:bg-sentinel-copperHover'
                          : 'bg-sentinel-mint/40 hover:bg-sentinel-mint'
                      }`}
                    />
                    <span className="font-mono-tech text-[9px] text-sentinel-muted opacity-80 group-hover:text-sentinel-copper transition-colors truncate">
                      {item.time.slice(3)}
                    </span>
                  </div>
                );
              })}
            </div>

            <div className="flex items-center justify-between text-[10px] font-mono-tech text-sentinel-muted pt-2 border-t border-sentinel-border/50 px-2">
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded bg-sentinel-copper" />
                Intermittent Video Frame Burst (H.264 I-Frame)
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded bg-sentinel-mint/40" />
                Nominal Encrypted P-Frame Transit
              </span>
            </div>
          </div>

          {/* Metric Strip for Traffic */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 pt-2">
            <div className="p-3 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech">
              <span className="text-[10px] text-sentinel-muted uppercase block">Packet Rate</span>
              <span className="text-xl font-bold text-sentinel-text mt-0.5 block">
                {mockTrafficClassification.metrics.packetRate} <span className="text-xs text-sentinel-muted font-normal">pkts/s</span>
              </span>
            </div>
            <div className="p-3 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech">
              <span className="text-[10px] text-sentinel-muted uppercase block">Mean Packet Size</span>
              <span className="text-xl font-bold text-sentinel-text mt-0.5 block">
                {mockTrafficClassification.metrics.averagePacketSize} <span className="text-xs text-sentinel-muted font-normal">Bytes</span>
              </span>
            </div>
            <div className="p-3 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech">
              <span className="text-[10px] text-sentinel-muted uppercase block">Burst Activity</span>
              <span className="text-sm font-bold text-sentinel-copper mt-1.5 block">
                {mockTrafficClassification.metrics.burstActivity}
              </span>
            </div>
            <div className="p-3 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech">
              <span className="text-[10px] text-sentinel-muted uppercase block">Directionality</span>
              <span className="text-xs font-bold text-sentinel-mint mt-1.5 block">
                {mockTrafficClassification.metrics.directionality}
              </span>
            </div>
            <div className="p-3 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech col-span-2 sm:col-span-1">
              <span className="text-[10px] text-sentinel-muted uppercase block">Flow Duration</span>
              <span className="text-xl font-bold text-sentinel-text mt-0.5 block">
                {mockTrafficClassification.metrics.flowDurationSec}s
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
              <span className="text-[10px] font-mono-tech text-sentinel-mint">
                91.4% CONFIDENCE
              </span>
            </div>

            <div className="space-y-4 font-mono-tech">
              <div className="p-3 rounded bg-sentinel-secondary/40 border border-sentinel-border space-y-1">
                <span className="text-[10px] text-sentinel-muted uppercase">Primary Inferred Class:</span>
                <div className="text-sm font-bold text-sentinel-copper">
                  {mockTrafficClassification.primaryClass}
                </div>
              </div>

              <div className="space-y-3">
                {mockTrafficClassification.distribution.map((item) => (
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
              <EyeOff className="w-4 h-4 text-sentinel-warning" />
              <h3 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                METADATA EXPOSURE ASSESSMENT
              </h3>
            </div>
            <StatusBadge status={mockMetadataExposure.risk} size="sm" />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-3 font-mono-tech text-xs">
              <div className="p-3 rounded bg-sentinel-secondary/30 border border-sentinel-border space-y-2 font-sans">
                <span className="font-mono-tech text-[10px] text-sentinel-copper uppercase font-bold block">
                  Encrypted Payload Behavioral Side-Channels:
                </span>
                <p className="text-sentinel-text text-xs leading-relaxed">
                  {mockMetadataExposure.notes}
                </p>
              </div>

              <div className="space-y-2 pt-2">
                <div className="flex items-center justify-between p-2 rounded bg-sentinel-secondary/40 border border-sentinel-border">
                  <span className="text-sentinel-muted">Packet-Size Fingerprinting</span>
                  <span className="text-sentinel-warning font-bold">DETECTED (1420B MTU)</span>
                </div>
                <div className="flex items-center justify-between p-2 rounded bg-sentinel-secondary/40 border border-sentinel-border">
                  <span className="text-sentinel-muted">Timing Patterns</span>
                  <span className="text-sentinel-warning font-bold">DETECTED (33.3ms)</span>
                </div>
                <div className="flex items-center justify-between p-2 rounded bg-sentinel-secondary/40 border border-sentinel-border">
                  <span className="text-sentinel-muted">Burst Patterns</span>
                  <span className="text-sentinel-warning font-bold">DETECTED (I-Frame)</span>
                </div>
                <div className="flex items-center justify-between p-2 rounded bg-sentinel-secondary/40 border border-sentinel-border">
                  <span className="text-sentinel-muted">Directionality Asymmetry</span>
                  <span className="text-sentinel-mint font-bold">84% INGRESS</span>
                </div>
              </div>
            </div>

            {/* Timeline Observations */}
            <div className="space-y-2 font-mono-tech text-xs">
              <span className="text-[10px] text-sentinel-muted uppercase font-bold block">
                Wire Interception Observations:
              </span>
              <div className="space-y-2">
                {mockMetadataExposure.timelineObservations.map((obs, i) => (
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
