'use client';

import React, { useState } from 'react';
import { 
  GitMerge, 
  Search, 
  Filter, 
  ExternalLink, 
  ShieldCheck, 
  AlertTriangle, 
  Key, 
  Terminal,
  Activity,
  ArrowRight
} from 'lucide-react';
import { MOCK_SESSIONS, MonitoredSession } from '@/lib/mock/securityData';

export default function SessionsPage() {
  const [sessions, setSessions] = useState<MonitoredSession[]>(MOCK_SESSIONS);
  const [selectedSession, setSelectedSession] = useState<MonitoredSession>(MOCK_SESSIONS[0]);
  const [filterType, setFilterType] = useState('ALL');

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-sentinel-border">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <GitMerge className="w-4 h-4 text-sentinel-copper" />
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-sentinel-text uppercase">
              DETAILED SESSION SECURITY ANALYSIS
            </h1>
          </div>
          <p className="text-xs text-sentinel-text-muted">
            Inspect individual IKEv2 and Child SA session state machines, SPI pairs, and rekey lifecycles.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-sentinel-mint font-semibold bg-sentinel-mint/10 px-2 py-1 rounded border border-sentinel-mint/30">
            ● 24 CONCURRENT SESSIONS
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Sessions List */}
        <div className="lg:col-span-5 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-sentinel-border">
            <span className="text-[11px] uppercase tracking-wider text-sentinel-text-muted font-bold">
              MONITORED TUNNEL FEEDS
            </span>
            <div className="flex items-center gap-1 text-[10px]">
              <button 
                onClick={() => setFilterType('ALL')} 
                className={`px-2 py-0.5 rounded ${filterType === 'ALL' ? 'bg-sentinel-copper text-white' : 'text-sentinel-text-muted'}`}
              >
                ALL
              </button>
              <button 
                onClick={() => setFilterType('WARN')} 
                className={`px-2 py-0.5 rounded ${filterType === 'WARN' ? 'bg-sentinel-warning text-black' : 'text-sentinel-text-muted'}`}
              >
                ALERTS
              </button>
            </div>
          </div>

          <div className="space-y-2.5">
            {sessions.map((sess) => {
              const isSelected = selectedSession.id === sess.id;
              return (
                <div
                  key={sess.id}
                  onClick={() => setSelectedSession(sess)}
                  className={`p-3.5 rounded-lg border cursor-pointer transition-all ${
                    isSelected
                      ? 'border-sentinel-copper bg-sentinel-panel shadow-md'
                      : 'border-sentinel-border bg-[#101214] hover:border-sentinel-border/80'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-bold text-xs text-sentinel-text flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full ${sess.status === 'CRIT' ? 'bg-sentinel-critical' : sess.status === 'ACTIVE' ? 'bg-sentinel-copper animate-pulse' : 'bg-sentinel-mint'}`} />
                      <span>{sess.id}</span>
                    </span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${sess.riskScore >= 80 ? 'bg-sentinel-mint/15 text-sentinel-mint' : sess.riskScore >= 60 ? 'bg-sentinel-warning/15 text-sentinel-warning' : 'bg-sentinel-critical/15 text-sentinel-critical'}`}>
                      SCORE {sess.riskScore}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-1 text-[11px] text-sentinel-text-muted">
                    <div>Path: <span className="text-sentinel-text">{sess.initiator.split(':')[0]}</span></div>
                    <div>Cipher: <span className="text-sentinel-copper">{sess.cipher}</span></div>
                    <div>Traffic: <span className="text-sentinel-text">{sess.trafficType}</span></div>
                    <div>PFS: <span className={sess.pfs === 'WARN' ? 'text-sentinel-warning' : sess.pfs === 'NO' ? 'text-sentinel-critical' : 'text-sentinel-mint'}>{sess.pfs}</span></div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Selected Session Deep-Dive */}
        <div className="lg:col-span-7 p-6 rounded-xl border border-sentinel-border bg-[#101214] space-y-5">
          <div className="flex items-center justify-between pb-3 border-b border-sentinel-border">
            <div>
              <div className="text-[10px] text-sentinel-text-muted uppercase">SESSION INSPECTOR</div>
              <div className="text-base font-bold text-sentinel-copper">{selectedSession.id}</div>
            </div>
            <span className="px-2.5 py-1 rounded border border-sentinel-border bg-[#151719] text-sentinel-mint font-bold text-xs">
              ESTABLISHED (RFC 4303)
            </span>
          </div>

          {/* Endpoints & SPI Details */}
          <div className="grid grid-cols-2 gap-3 p-3.5 rounded-lg border border-sentinel-border bg-[#151719]">
            <div>
              <div className="text-[10px] text-sentinel-text-muted uppercase">INITIATOR ENDPOINT</div>
              <div className="font-bold text-sentinel-text mt-0.5">{selectedSession.initiator}</div>
              <div className="text-[10px] text-sentinel-copper mt-1">SPI IN: {selectedSession.spiIn}</div>
            </div>
            <div>
              <div className="text-[10px] text-sentinel-text-muted uppercase">RESPONDER GATEWAY</div>
              <div className="font-bold text-sentinel-text mt-0.5">{selectedSession.responder}</div>
              <div className="text-[10px] text-sentinel-copper mt-1">SPI OUT: {selectedSession.spiOut}</div>
            </div>
          </div>

          {/* Cryptographic State Matrix */}
          <div>
            <div className="text-[11px] font-bold text-sentinel-text uppercase mb-2">
              CRYPTOGRAPHIC PARAMETERS
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center text-[10px]">
              <div className="p-2.5 rounded border border-sentinel-border bg-[#0B0C0D]">
                <div className="text-sentinel-text-muted">CIPHER</div>
                <div className="font-bold text-sentinel-text mt-0.5">{selectedSession.cipher}</div>
              </div>
              <div className="p-2.5 rounded border border-sentinel-border bg-[#0B0C0D]">
                <div className="text-sentinel-text-muted">DIFFIE-HELLMAN</div>
                <div className="font-bold text-sentinel-copper mt-0.5">{selectedSession.dhGroup}</div>
              </div>
              <div className="p-2.5 rounded border border-sentinel-border bg-[#0B0C0D]">
                <div className="text-sentinel-text-muted">HASH / PRF</div>
                <div className="font-bold text-sentinel-text mt-0.5">{selectedSession.hash}</div>
              </div>
              <div className="p-2.5 rounded border border-sentinel-border bg-[#0B0C0D]">
                <div className="text-sentinel-text-muted">FORWARD SECRECY</div>
                <div className={`font-bold mt-0.5 ${selectedSession.pfs === 'WARN' ? 'text-sentinel-warning' : selectedSession.pfs === 'NO' ? 'text-sentinel-critical' : 'text-sentinel-mint'}`}>
                  {selectedSession.pfs}
                </div>
              </div>
            </div>
          </div>

          {/* Telemetry Stats */}
          <div className="p-3.5 rounded-lg border border-sentinel-border bg-[#151719] space-y-1.5 text-[11px]">
            <div className="flex justify-between">
              <span className="text-sentinel-text-muted">Total Volume Transferred:</span>
              <span className="font-bold text-sentinel-text">{selectedSession.bytesTransferred}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sentinel-text-muted">Accumulated Encapsulated Frames:</span>
              <span className="font-bold text-sentinel-text">{selectedSession.packets.toLocaleString()} pkts</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sentinel-text-muted">ML Inferred Cleartext Protocol:</span>
              <span className="font-bold text-sentinel-copper">{selectedSession.trafficType} (Confidence: 94.2%)</span>
            </div>
          </div>

          <div className="pt-2 flex items-center justify-between text-[11px] text-sentinel-text-muted">
            <span>Audit Anchor: RFC 7296 §1.3</span>
            <button className="px-3 py-1.5 rounded border border-sentinel-copper bg-sentinel-copper text-white dark:text-[#0B0C0D] font-bold hover:bg-sentinel-copper/90 transition-colors">
              Re-audit Session Grammars
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
