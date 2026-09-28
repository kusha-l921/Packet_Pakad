'use client';

import React from 'react';
import { Settings, Save, Shield, Cpu, Sliders } from 'lucide-react';

export default function SettingsPage() {
  return (
    <div className="space-y-6 font-mono text-xs max-w-4xl">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-sentinel-border">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Settings className="w-4 h-4 text-sentinel-copper" />
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-sentinel-text uppercase">
              SYSTEM CONFIGURATION & ENGINE ADAPTERS
            </h1>
          </div>
          <p className="text-xs text-sentinel-text-muted">
            Configure sovereign compliance rule thresholds, zero-copy buffer allocations, and FastAPI endpoint endpoints.
          </p>
        </div>

        <button className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-sentinel-copper bg-sentinel-copper text-white dark:text-[#0B0C0D] font-bold hover:bg-sentinel-copper/90 transition-colors">
          <Save className="w-3.5 h-3.5" />
          <span>Save Configuration</span>
        </button>
      </div>

      <div className="space-y-5">
        <div className="p-5 rounded-xl border border-sentinel-border bg-[#101214] space-y-4">
          <div className="text-xs font-bold text-sentinel-copper uppercase">
            1. FASTAPI ENGINE BACKEND ADAPTER
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="text-sentinel-text-muted block mb-1">Inference Service URL</label>
              <input
                type="text"
                defaultValue="http://127.0.0.1:8000/api/v1/analyze"
                className="w-full px-3 py-1.5 rounded border border-sentinel-border bg-[#151719] text-sentinel-text text-xs"
              />
            </div>
            <div>
              <label className="text-sentinel-text-muted block mb-1">Request Timeout (ms)</label>
              <input
                type="number"
                defaultValue="50"
                className="w-full px-3 py-1.5 rounded border border-sentinel-border bg-[#151719] text-sentinel-text text-xs"
              />
            </div>
          </div>
        </div>

        <div className="p-5 rounded-xl border border-sentinel-border bg-[#101214] space-y-4">
          <div className="text-xs font-bold text-sentinel-copper uppercase">
            2. HARDENING BASELINE THRESHOLDS
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="text-sentinel-text-muted block mb-1">Max Rekey Lifetime (seconds)</label>
              <input
                type="number"
                defaultValue="7200"
                className="w-full px-3 py-1.5 rounded border border-sentinel-border bg-[#151719] text-sentinel-text text-xs"
              />
            </div>
            <div>
              <label className="text-sentinel-text-muted block mb-1">Replay Window Size (packets)</label>
              <input
                type="number"
                defaultValue="64"
                className="w-full px-3 py-1.5 rounded border border-sentinel-border bg-[#151719] text-sentinel-text text-xs"
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
