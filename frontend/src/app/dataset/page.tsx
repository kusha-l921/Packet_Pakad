'use client';

import React from 'react';
import { AppShell } from '@/components/layout/AppShell';
import { NoDataState } from '@/components/common/NoDataState';
import { useSession } from '@/context/SessionContext';
import { mockDatasetMetrics } from '@/data/dataset';
import { ProgressBar } from '@/components/common/TechnicalField';
import {
  Database,
  Layers,
  PieChart,
  CheckCircle2,
  Download,
  Share2,
  Cpu,
  BarChart2,
} from 'lucide-react';

export default function DatasetPage() {
  const { sessions } = useSession();

  if (sessions.length === 0) {
    return (
      <AppShell>
        <div className="space-y-6 max-w-7xl mx-auto">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-sentinel-border">
            <div>
              <div className="flex items-center gap-2">
                <Database className="w-5 h-5 text-sentinel-copper" />
                <h1 className="font-mono-tech text-base md:text-lg font-bold tracking-wider text-sentinel-text uppercase">
                  Synthetic Ground Truth Dataset
                </h1>
              </div>
              <p className="text-xs text-sentinel-muted mt-0.5">
                Multi-modal IPsec PCAP benchmark captures with labelled ground-truth verification metadata.
              </p>
            </div>
          </div>

          <NoDataState
            title="NO DATASET TO PROCESS"
            description="No active or historical IPsec sessions have been recorded to benchmark or train flow classifiers. Deploy the virtual testbed to generate real traffic datasets."
            actionText="LAUNCH TESTBED & START TESTING"
            actionHref="/testbed"
          />
        </div>
      </AppShell>
    );
  }
  return (
    <AppShell>
      <div className="space-y-6 max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-sentinel-border">
          <div>
            <div className="flex items-center gap-2">
              <Database className="w-5 h-5 text-sentinel-copper" />
              <h1 className="font-mono-tech text-base md:text-lg font-bold tracking-wider text-sentinel-text uppercase">
                Synthetic Ground Truth Dataset
              </h1>
            </div>
            <p className="text-xs text-sentinel-muted mt-0.5">
              Multi-modal IPsec PCAP benchmark captures with labelled ground-truth verification metadata.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                const blob = new Blob([JSON.stringify(mockDatasetMetrics, null, 2)], {
                  type: 'application/json',
                });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'ipsec_ground_truth_dataset_manifest.json';
                a.click();
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-sentinel-copper text-sentinel-bg font-mono-tech text-xs font-semibold hover:bg-sentinel-copperHover transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              Download Dataset Manifest
            </button>
          </div>
        </div>

        {/* Top Split Metrics */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="panel-technical p-4 rounded-lg space-y-1">
            <span className="text-[10px] font-mono-tech tracking-wider uppercase text-sentinel-muted">
              Total Labeled Samples
            </span>
            <div className="font-mono-tech text-2xl font-bold text-sentinel-text">
              {mockDatasetMetrics.totalSamples.toLocaleString()}
            </div>
            <div className="text-[10px] font-mono-tech text-sentinel-copper">
              1,420 Distinct Flow Sessions
            </div>
          </div>

          <div className="panel-technical p-4 rounded-lg space-y-1">
            <span className="text-[10px] font-mono-tech tracking-wider uppercase text-sentinel-muted">
              Training Split (70%)
            </span>
            <div className="font-mono-tech text-2xl font-bold text-sentinel-text">
              {mockDatasetMetrics.trainSplit.toLocaleString()}
            </div>
            <div className="text-[10px] font-mono-tech text-sentinel-muted">
              Supervised model training
            </div>
          </div>

          <div className="panel-technical p-4 rounded-lg space-y-1">
            <span className="text-[10px] font-mono-tech tracking-wider uppercase text-sentinel-muted">
              Validation Split (15%)
            </span>
            <div className="font-mono-tech text-2xl font-bold text-sentinel-mint">
              {mockDatasetMetrics.valSplit.toLocaleString()}
            </div>
            <div className="text-[10px] font-mono-tech text-sentinel-muted">
              Hyperparameter tuning
            </div>
          </div>

          <div className="panel-technical p-4 rounded-lg space-y-1">
            <span className="text-[10px] font-mono-tech tracking-wider uppercase text-sentinel-muted">
              Testing Split (15%)
            </span>
            <div className="font-mono-tech text-2xl font-bold text-sentinel-copper">
              {mockDatasetMetrics.testSplit.toLocaleString()}
            </div>
            <div className="text-[10px] font-mono-tech text-sentinel-muted">
              Unbiased evaluation
            </div>
          </div>
        </div>

        {/* 2-Column: Traffic Class Distribution & Topology Configurations */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Traffic Classes */}
          <div className="panel-technical p-5 rounded-lg space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
              <div className="flex items-center gap-2">
                <PieChart className="w-4 h-4 text-sentinel-copper" />
                <h2 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                  Traffic Class Distribution
                </h2>
              </div>
              <span className="text-[10px] font-mono-tech text-sentinel-muted">
                5 Primary Protocols
              </span>
            </div>

            <div className="space-y-3.5 font-mono-tech">
              {mockDatasetMetrics.classes.map((cls) => (
                <div key={cls.className} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-sentinel-text">{cls.className}</span>
                    <span className="text-sentinel-muted">
                      {cls.count.toLocaleString()} pkts ({cls.pct}%)
                    </span>
                  </div>
                  <ProgressBar
                    value={cls.pct}
                    max={100}
                    color={cls.pct > 30 ? 'copper' : 'mint'}
                    height="h-1.5"
                  />
                </div>
              ))}
            </div>
          </div>

          {/* Configuration Combinations */}
          <div className="panel-technical p-5 rounded-lg space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-sentinel-copper" />
                <h2 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                  VPN Topology Configurations
                </h2>
              </div>
              <span className="text-[10px] font-mono-tech text-sentinel-muted">
                IKE / Mode / Cipher / DH / PFS / IP
              </span>
            </div>

            <div className="space-y-3 font-mono-tech text-xs">
              {mockDatasetMetrics.configs.map((cfg, i) => (
                <div
                  key={i}
                  className="p-2.5 rounded bg-sentinel-secondary/30 border border-sentinel-border flex items-center justify-between gap-3"
                >
                  <span className="text-sentinel-text truncate max-w-sm">
                    {cfg.label}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-sentinel-deep border border-sentinel-border text-sentinel-copper font-bold flex-shrink-0">
                    {cfg.count.toLocaleString()} samples
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Ground Truth Accuracy Benchmarks */}
        <div className="panel-technical rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-sentinel-mint" />
              <h2 className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                Ground Truth Model Accuracy & Validation Metrics
              </h2>
            </div>
            <span className="text-[10px] font-mono-tech text-sentinel-muted">
              Random Forest + 1D-CNN vs Known Encrypted Payloads
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono-tech text-xs border-collapse">
              <thead className="bg-sentinel-secondary/60 text-sentinel-muted text-[10px] uppercase border-b border-sentinel-border">
                <tr>
                  <th className="py-2.5 px-3">Protocol Application Class</th>
                  <th className="py-2.5 px-3">Precision</th>
                  <th className="py-2.5 px-3">Recall</th>
                  <th className="py-2.5 px-3">F1-Score</th>
                  <th className="py-2.5 px-3 text-right">Verification Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sentinel-border">
                {mockDatasetMetrics.groundTruthAccuracy.map((row) => (
                  <tr key={row.class} className="hover:bg-sentinel-elevated transition-colors">
                    <td className="py-3 px-3 font-semibold text-sentinel-text">
                      {row.class}
                    </td>
                    <td className="py-3 px-3 text-sentinel-copper">
                      {(row.precision * 100).toFixed(1)}%
                    </td>
                    <td className="py-3 px-3 text-sentinel-copper">
                      {(row.recall * 100).toFixed(1)}%
                    </td>
                    <td className="py-3 px-3 font-bold text-sentinel-mint">
                      {(row.f1 * 100).toFixed(1)}%
                    </td>
                    <td className="py-3 px-3 text-right">
                      <span className="px-2 py-0.5 rounded bg-sentinel-mint/10 border border-sentinel-mint/30 text-sentinel-mint text-[10px] font-bold">
                        VERIFIED
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
