'use client';

import React, { useState } from 'react';
import { Sliders, Play, Square, RefreshCw, Terminal, Activity, CheckCircle2 } from 'lucide-react';

export default function TestbedPage() {
  const [running, setRunning] = useState(true);

  return (
    <div className="space-y-6 font-mono text-xs">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-sentinel-border">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Sliders className="w-4 h-4 text-sentinel-copper" />
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-sentinel-text uppercase">
              TESTBED ENVIRONMENT & TRAFFIC GENERATOR
            </h1>
          </div>
          <p className="text-xs text-sentinel-text-muted">
            StrongSwan virtual lab container control, traffic generator injection, and live capture orchestrator.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {running ? (
            <button
              onClick={() => setRunning(false)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-sentinel-critical bg-sentinel-critical/20 text-sentinel-critical font-bold hover:bg-sentinel-critical/30 transition-colors"
            >
              <Square className="w-3 h-3 fill-current" />
              <span>Halt Generator</span>
            </button>
          ) : (
            <button
              onClick={() => setRunning(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-sentinel-mint bg-sentinel-mint/20 text-sentinel-mint font-bold hover:bg-sentinel-mint/30 transition-colors"
            >
              <Play className="w-3 h-3 fill-current" />
              <span>Launch Testbed</span>
            </button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="p-4 rounded-xl border border-sentinel-border bg-[#101214]">
          <div className="text-[10px] text-sentinel-text-muted uppercase mb-1">TESTBED CLIENT</div>
          <div className="text-sm font-bold text-sentinel-text">client (10.0.1.12)</div>
          <div className="text-[11px] text-sentinel-mint mt-1">● strongSwan 5.9.11 Docker</div>
        </div>

        <div className="p-4 rounded-xl border border-sentinel-border bg-[#101214]">
          <div className="text-[10px] text-sentinel-text-muted uppercase mb-1">SECURITY GATEWAY</div>
          <div className="text-sm font-bold text-sentinel-text">gateway (10.0.2.20)</div>
          <div className="text-[11px] text-sentinel-mint mt-1">● VICI Control Daemon Active</div>
        </div>

        <div className="p-4 rounded-xl border border-sentinel-border bg-[#101214]">
          <div className="text-[10px] text-sentinel-text-muted uppercase mb-1">TRAFFIC PROFILE</div>
          <div className="text-sm font-bold text-sentinel-copper">H.264 VBR Synthetic Stream</div>
          <div className="text-[11px] text-sentinel-text-muted mt-1">1.2 Mbps • 30 fps Frame Cadence</div>
        </div>
      </div>

      <div className="p-5 rounded-xl border border-sentinel-border bg-[#101214]">
        <div className="flex items-center gap-2 pb-3 mb-3 border-b border-sentinel-border text-sentinel-text">
          <Terminal className="w-4 h-4 text-sentinel-copper" />
          <span className="font-bold text-xs uppercase">TESTBED CONTROLLER LOG OUTPUT</span>
        </div>
        <div className="p-3.5 rounded bg-[#0B0C0D] border border-sentinel-border text-[11px] text-sentinel-text-muted space-y-1">
          <div>[TESTBED] Initiating IKEv2 testbed topology: client (10.0.1.12) &lt;-&gt; gateway (10.0.2.20)</div>
          <div>[SWANCTL] Loaded connection &apos;gw-del-hq&apos;: proposals=aes256gcm16-sha384-modp2048</div>
          <div>[TRAFFIC] Injecting synthetic H.264 video RTP stream over UDP 4500 ESP envelope</div>
          <div>[STATUS] Live capture stream running: 1,840 pkts/sec into AF_PACKET analyzer</div>
        </div>
      </div>
    </div>
  );
}
