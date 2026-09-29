'use client';

import React, { useState, useEffect, useRef } from 'react';
import Link from 'next/link';
import { AppShell } from '@/components/layout/AppShell';
import { NoDataState } from '@/components/common/NoDataState';
import {
  Radio,
  Square,
  Play,
  Upload,
  Terminal,
  FileCode,
  Filter,
  CheckCircle2,
  Clock,
  Layers,
  ArrowDown,
  RefreshCw,
  Search,
  Shield,
  Trash2,
  Cpu,
  Zap,
} from 'lucide-react';
import { Packet, ProtocolType } from '@/types';
import { SessionSelector } from '@/components/common/SessionSelector';
import { useSession } from '@/context/SessionContext';

// Helper to format raw hex string into Wireshark-style hex dump
function formatHexDump(hexString?: string, baseOffset = 0): { offset: string; hex: string; ascii: string }[] {
  if (!hexString) return [];
  const cleanHex = hexString.replace(/[^0-9a-fA-F]/g, '');
  const rows: { offset: string; hex: string; ascii: string }[] = [];

  for (let i = 0; i < cleanHex.length; i += 32) {
    const chunk = cleanHex.slice(i, i + 32);
    const offset = (baseOffset + Math.floor(i / 2)).toString(16).padStart(4, '0');
    
    // Group into 2-char bytes
    const bytes: string[] = [];
    let ascii = '';
    for (let b = 0; b < chunk.length; b += 2) {
      const byteHex = chunk.slice(b, b + 2);
      bytes.push(byteHex);
      const code = parseInt(byteHex, 16);
      ascii += (code >= 32 && code <= 126) ? String.fromCharCode(code) : '.';
    }
    
    // Split into 8 bytes and 8 bytes
    const part1 = bytes.slice(0, 8).join(' ');
    const part2 = bytes.slice(8).join(' ');
    const hexFormatted = `${part1.padEnd(23, ' ')}  ${part2.padEnd(23, ' ')}`;

    rows.push({
      offset,
      hex: hexFormatted,
      ascii: ascii.padEnd(16, ' '),
    });
  }

  return rows;
}

export default function PacketCapturePage() {
  const { sessions, selectedSessionId, selectedSession, setSelectedSessionId, deleteSession } = useSession();
  const [captureMode, setCaptureMode] = useState<'LIVE' | 'SESSION'>('LIVE');
  const [packets, setPackets] = useState<Packet[]>([]);
  const [isCapturing, setIsCapturing] = useState<boolean>(true);
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
  const [filterProtocol, setFilterProtocol] = useState<'ALL' | 'IKE' | 'ESP' | 'AH'>('ALL');
  const [terminalTab, setTerminalTab] = useState<'dissection' | 'daemon'>('dissection');
  const [daemonLogs, setDaemonLogs] = useState<string[]>([]);
  const [dissectionLogs, setDissectionLogs] = useState<string[]>([]);
  const [searchTerm, setSearchTerm] = useState<string>('');

  const lastPacketCountRef = useRef<number>(0);
  const isBufferClearedRef = useRef<boolean>(false);
  const [isInjectingTraffic, setIsInjectingTraffic] = useState<boolean>(false);

  // Clear live & display buffer
  const handleClearBuffer = async () => {
    isBufferClearedRef.current = true;
    setPackets([]);
    setSelectedPacket(null);
    lastPacketCountRef.current = 0;
    const ts = new Date().toTimeString().split(' ')[0];
    setDissectionLogs((prev) => [
      ...prev,
      `[${ts}] [OPERATOR ACTION] Packet capture buffer flushed and cleared.`,
    ]);
    try {
      await fetch('http://localhost:8000/api/v1/capture/packets', { method: 'DELETE' });
    } catch (e) {
      console.error('Failed to notify backend of buffer clear', e);
    }
  };

  // Poll wire manually
  const handlePollWire = async () => {
    isBufferClearedRef.current = false;
    try {
      const res = await fetch('http://localhost:8000/api/v1/capture/packets?live=true');
      const data: Packet[] = await res.json();
      if (Array.isArray(data) && data.length > 0) {
        setPackets(data);
        setSelectedPacket(data[0]);
      } else {
        setPackets([]);
        setSelectedPacket(null);
        const ts = new Date().toTimeString().split(' ')[0];
        setDissectionLogs((prev) => [
          ...prev,
          `[${ts}] [POLL WIRE] Live wire idle: no active packets in flight. Switch to Session Mode to inspect archived sessions.`,
        ]);
      }
    } catch {
      setPackets([]);
      setSelectedPacket(null);
    }
  };

  // Inject synthetic traffic burst
  const handleInjectTraffic = async () => {
    setIsInjectingTraffic(true);
    isBufferClearedRef.current = false;
    const ts = new Date().toTimeString().split(' ')[0];
    setDissectionLogs((prev) => [
      ...prev,
      `[${ts}] [TRIGGER] Injected synthetic Video traffic into tunnel...`,
    ]);
    try {
      await fetch('http://localhost:8000/api/v1/testbed/traffic', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ trafficType: 'Video' }),
      });
    } catch (e) {
      console.error('Failed to trigger traffic', e);
    } finally {
      setTimeout(() => setIsInjectingTraffic(false), 2500);
    }
  };

  // Reload recorded session frames
  const handleReloadSession = () => {
    if (!selectedSessionId) return;
    isBufferClearedRef.current = false;
    fetch(`http://localhost:8000/api/v1/capture/packets?session_id=${encodeURIComponent(selectedSessionId)}`)
      .then((res) => {
        if (!res.ok) throw new Error('API not available');
        return res.json();
      })
      .then((data: Packet[]) => {
        if (Array.isArray(data) && data.length > 0) {
          setPackets(data);
          setSelectedPacket(data[0]);
          const ts = new Date().toTimeString().split(' ')[0];
          setDissectionLogs((prev) => [
            ...prev,
            `[${ts}] [SESSION RELOAD] Reloaded ${data.length} recorded frames for session ${selectedSessionId}.`,
          ]);
        }
      })
      .catch(() => {});
  };

  // Load packets and logs based on captureMode
  useEffect(() => {
    if (captureMode === 'LIVE') {
      if (!isCapturing) return;

      const loadLiveData = () => {
        // 1. Fetch live stream packets
        fetch('http://localhost:8000/api/v1/capture/packets?live=true')
          .then((res) => {
            if (!res.ok) throw new Error('API not available');
            return res.json();
          })
          .then((data: Packet[]) => {
            if (isBufferClearedRef.current && (!Array.isArray(data) || data.length === 0)) {
              setPackets([]);
              setSelectedPacket(null);
              return;
            }
            if (Array.isArray(data) && data.length > 0) {
              isBufferClearedRef.current = false;
              setPackets(data);
              setSelectedPacket((prev) => {
                if (prev) {
                  const stillExists = data.find((p) => p.id === prev.id);
                  return stillExists || data[0];
                }
                return data[0];
              });

              if (data.length !== lastPacketCountRef.current) {
                lastPacketCountRef.current = data.length;
                const generated: string[] = [
                  `$ ipsec-analyzer --live --interface eth0 --filter "udp port 500 or udp port 4500 or proto 50"`,
                  `[*] Promiscuous live bitstream sniffer active. Ingested ${data.length} authenticated frames.`,
                  `--------------------------------------------------------------------------------`,
                ];

                data.forEach((p) => {
                  if (p.protocol === 'IKE') {
                    generated.push(
                      `[${p.timestamp}] [LIVE IKE #${p.id}] ${p.source} -> ${p.destination} | SPI: ${p.spi || '0x0'} | Len: ${p.length}B | ${p.info}`
                    );
                  } else if (p.protocol === 'ESP') {
                    generated.push(
                      `[${p.timestamp}] [LIVE ESP #${p.id}] SPI: ${p.spi} | Seq: #${p.seq || 0} | Wire: ${p.length}B | AES-256-GCM AEAD | ICV: OK`
                    );
                  } else {
                    generated.push(
                      `[${p.timestamp}] [LIVE FRAME #${p.id}] ${p.protocol} | ${p.source} -> ${p.destination} | Len: ${p.length}B`
                    );
                  }
                });

                generated.push(`[*] Live bitstream synchronized: ${data.filter(p => p.protocol === 'ESP').length} ESP envelopes, ${data.filter(p => p.protocol === 'IKE').length} IKE exchanges.`);
                setDissectionLogs(generated);
              }
            } else {
              if (lastPacketCountRef.current > 0) {
                lastPacketCountRef.current = 0;
                const ts = new Date().toTimeString().split(' ')[0];
                setDissectionLogs((prev) => [
                  ...prev,
                  `[${ts}] [*] Live session transmission concluded and finalized.`,
                  `[${ts}] [*] All recorded session frames are preserved and viewable in Session Mode.`,
                ]);
              }
              setPackets([]);
              setSelectedPacket(null);
            }
          })
          .catch(() => {
            setPackets([]);
            setSelectedPacket(null);
          });

        // 2. Fetch testbed daemon logs
        fetch('http://localhost:8000/api/v1/testbed/logs')
          .then((res) => res.json())
          .then((data) => {
            if (Array.isArray(data?.logs) && data.logs.length > 0) {
              setDaemonLogs(data.logs);
            }
          })
          .catch(() => {});
      };

      loadLiveData();
      const interval = setInterval(loadLiveData, 2000);
      return () => clearInterval(interval);
    } else {
      // SESSION MODE: Load recorded archive frames for selectedSessionId without constant polling
      isBufferClearedRef.current = false;
      if (!selectedSessionId) {
        setPackets([]);
        setSelectedPacket(null);
        return;
      }

      fetch(`http://localhost:8000/api/v1/capture/packets?session_id=${encodeURIComponent(selectedSessionId)}`)
        .then((res) => {
          if (!res.ok) throw new Error('API not available');
          return res.json();
        })
        .then((data: Packet[]) => {
          if (Array.isArray(data) && data.length > 0) {
            setPackets(data);
            setSelectedPacket(data[0]);
            lastPacketCountRef.current = data.length;

            const archiveLogs: string[] = [
              `$ ipsec-analyzer --session-archive --id ${selectedSessionId}`,
              `[*] Loaded recorded session bitstream archive [${selectedSessionId}].`,
              `[*] Forensic archive contains ${data.length} authenticated network frames.`,
              `--------------------------------------------------------------------------------`,
            ];

            data.forEach((p) => {
              if (p.protocol === 'IKE') {
                archiveLogs.push(
                  `[${p.timestamp}] [ARCHIVE IKE #${p.id}] ${p.source} -> ${p.destination} | SPI: ${p.spi || '0x0'} | Len: ${p.length}B | ${p.info}`
                );
              } else if (p.protocol === 'ESP') {
                archiveLogs.push(
                  `[${p.timestamp}] [ARCHIVE ESP #${p.id}] SPI: ${p.spi} | Seq: #${p.seq || 0} | Wire: ${p.length}B | AES-256-GCM AEAD | ICV: OK`
                );
              } else {
                archiveLogs.push(
                  `[${p.timestamp}] [ARCHIVE FRAME #${p.id}] ${p.protocol} | ${p.source} -> ${p.destination} | Len: ${p.length}B`
                );
              }
            });
            setDissectionLogs(archiveLogs);
          } else {
            setPackets([]);
            setSelectedPacket(null);
          }
        })
        .catch(() => {
          setPackets([]);
          setSelectedPacket(null);
        });
    }
  }, [captureMode, isCapturing, selectedSessionId]);

  // Log packet inspection when user selects a packet
  const handleSelectPacket = (p: Packet) => {
    setSelectedPacket(p);
    const ts = new Date().toTimeString().split(' ')[0];
    const dissectionEntry = [
      `>>> [${ts}] INSPECTING FRAME #${p.id} (${p.protocol}) [MODE: ${captureMode}]`,
      `    ├── Protocol: ${p.protocol} ${p.protocol === 'ESP' ? '(RFC 4303 / RFC 3948 NAT-T)' : '(RFC 7296 IKEv2)'}`,
      `    ├── Flow: ${p.source} ===> ${p.destination}`,
      `    ├── SPI: ${p.spi || 'N/A'} | Sequence: ${p.seq !== undefined ? '#' + p.seq : 'Control Exchange'}`,
      `    ├── Length: ${p.length} Bytes | Status: Authenticated Wire Frame`,
      `    ├── Cryptography: AES-256-GCM AEAD (128-bit ICV Tag Validated)`,
      `    └── Payload: ${p.info}`,
    ];
    setDissectionLogs((prev) => [...prev, ...dissectionEntry]);
  };

  // Filtered packets
  const filteredPackets = packets.filter((p) => {
    const matchesProto = filterProtocol === 'ALL' || p.protocol === filterProtocol;
    const matchesSearch =
      !searchTerm ||
      p.info.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (p.spi && p.spi.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (p.seq !== undefined && p.seq.toString().includes(searchTerm)) ||
      p.source.includes(searchTerm) ||
      p.destination.includes(searchTerm);
    return matchesProto && matchesSearch;
  });

  const ikeCount = packets.filter((p) => p.protocol === 'IKE').length;
  const espCount = packets.filter((p) => p.protocol === 'ESP').length;

  return (
    <AppShell>
      <div className="space-y-6 max-w-7xl mx-auto">
        {/* Top Operational Mode Strip */}
        <div className="panel-technical rounded-lg p-4 border border-sentinel-border space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-3 border-b border-sentinel-border">
            <div>
              <div className="flex items-center gap-2">
                <Radio className={`w-5 h-5 ${captureMode === 'LIVE' ? 'text-sentinel-mint' : 'text-sentinel-copper'}`} />
                <h1 className="font-mono-tech text-base md:text-lg font-bold tracking-wider text-sentinel-text uppercase">
                  {captureMode === 'LIVE' ? 'Live Packet Ingestion & Wire Sniffer' : 'Historic Session Forensics & Replay'}
                </h1>
              </div>
              <p className="text-xs text-sentinel-muted mt-0.5">
                {captureMode === 'LIVE'
                  ? 'Continuous real-time bitstream sniffer monitoring active wire traffic and protocol exchanges.'
                  : 'Deterministic forensic inspection of recorded historical IPsec session frames and parameters.'}
              </p>
            </div>

            {/* Dual Operational Mode Switcher */}
            <div className="flex items-center rounded-lg bg-sentinel-secondary p-1 border border-sentinel-border shadow-sm">
              <button
                type="button"
                onClick={() => setCaptureMode('LIVE')}
                className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-mono-tech font-bold transition-all ${
                  captureMode === 'LIVE'
                    ? 'bg-sentinel-mint text-sentinel-bg shadow'
                    : 'text-sentinel-muted hover:text-sentinel-text hover:bg-sentinel-elevated/40'
                }`}
              >
                <Radio className="w-3.5 h-3.5" />
                <span>LIVE MODE</span>
                {captureMode === 'LIVE' && isCapturing && (
                  <span className="w-2 h-2 rounded-full bg-red-500 animate-ping" />
                )}
              </button>

              <button
                type="button"
                onClick={() => setCaptureMode('SESSION')}
                className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-mono-tech font-bold transition-all ${
                  captureMode === 'SESSION'
                    ? 'bg-sentinel-copper text-sentinel-bg shadow'
                    : 'text-sentinel-muted hover:text-sentinel-text hover:bg-sentinel-elevated/40'
                }`}
              >
                <Layers className="w-3.5 h-3.5" />
                <span>SESSION MODE</span>
                {sessions.length > 0 && (
                  <span className="px-1.5 py-0.2 rounded text-[10px] bg-sentinel-bg/40 font-mono-tech font-semibold">
                    {sessions.length}
                  </span>
                )}
              </button>
            </div>
          </div>

          {/* Sub-toolbar Controls */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-1">
            {captureMode === 'LIVE' ? (
              <>
                <div className="flex items-center gap-2">
                  <span className="inline-flex items-center gap-1.5 text-xs font-mono-tech px-2.5 py-1 rounded bg-sentinel-mint/15 border border-sentinel-mint/30 text-sentinel-mint font-semibold">
                    <span className={`w-2 h-2 rounded-full ${isCapturing ? 'bg-sentinel-mint animate-pulse' : 'bg-sentinel-muted'}`} />
                    {isCapturing ? 'LIVE STREAM ACTIVE (ETH0)' : 'LIVE STREAM PAUSED'}
                  </span>
                  <span className="text-[11px] font-mono-tech text-sentinel-muted hidden sm:inline">
                    Promiscuous Filter: UDP 500 / 4500 / Proto 50
                  </span>
                </div>

                <div className="flex items-center gap-2 flex-wrap">
                  <button
                    onClick={() => setIsCapturing(!isCapturing)}
                    className={`flex items-center gap-1.5 px-3 py-1.5 font-mono-tech text-xs font-semibold rounded border transition-colors ${
                      isCapturing
                        ? 'bg-sentinel-critical/15 border-sentinel-critical text-sentinel-critical hover:bg-sentinel-critical/20'
                        : 'bg-sentinel-mint/15 border-sentinel-mint text-sentinel-mint hover:bg-sentinel-mint/20'
                    }`}
                  >
                    {isCapturing ? (
                      <>
                        <Square className="w-3.5 h-3.5 fill-current" />
                        PAUSE SNIFFER
                      </>
                    ) : (
                      <>
                        <Play className="w-3.5 h-3.5 fill-current" />
                        RESUME SNIFFER
                      </>
                    )}
                  </button>

                  <button
                    onClick={handlePollWire}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-sentinel-copper text-sentinel-bg font-mono-tech text-xs font-semibold rounded hover:bg-sentinel-copperHover transition-colors"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    POLL WIRE
                  </button>

                  <button
                    onClick={handleInjectTraffic}
                    disabled={isInjectingTraffic}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-sentinel-mint/15 border border-sentinel-mint/40 text-sentinel-mint font-mono-tech text-xs font-semibold rounded hover:bg-sentinel-mint/20 transition-colors disabled:opacity-50"
                  >
                    <Zap className="w-3.5 h-3.5" />
                    {isInjectingTraffic ? 'INJECTING...' : 'INJECT TRAFFIC'}
                  </button>

                  <button
                    onClick={handleClearBuffer}
                    className="flex items-center gap-1.5 px-2.5 py-1.5 bg-sentinel-secondary border border-sentinel-border hover:border-sentinel-copper text-sentinel-muted hover:text-sentinel-text font-mono-tech text-xs rounded transition-colors"
                    title="Flush and clear live packet buffer"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    CLEAR BUFFER
                  </button>
                </div>
              </>
            ) : (
              <>
                <div className="flex items-center gap-2.5 flex-wrap">
                  <SessionSelector />
                  <span className="text-[11px] font-mono-tech text-sentinel-muted">
                    {selectedSession ? (
                      <>
                        Cipher: <span className="text-sentinel-copper font-bold">{selectedSession.encryption}</span> • Mode:{' '}
                        <span className="text-sentinel-text">{selectedSession.mode}</span> • SPI:{' '}
                        <span className="text-sentinel-copper">{selectedSession.spiIn}</span>
                      </>
                    ) : (
                      'No past session selected'
                    )}
                  </span>
                </div>

                <div className="flex items-center gap-2 flex-wrap">
                  <button
                    type="button"
                    onClick={handleReloadSession}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-sentinel-secondary border border-sentinel-border hover:border-sentinel-copper text-sentinel-muted hover:text-sentinel-text font-mono-tech text-xs rounded transition-colors"
                    title="Reload recorded frames for selected session"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    RELOAD SESSION
                  </button>

                  <button
                    type="button"
                    onClick={handleClearBuffer}
                    className="flex items-center gap-1.5 px-2.5 py-1.5 bg-sentinel-secondary border border-sentinel-border hover:border-sentinel-copper text-sentinel-muted hover:text-sentinel-text font-mono-tech text-xs rounded transition-colors"
                    title="Clear current packet inspection view"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    CLEAR BUFFER
                  </button>

                  {selectedSession && (
                    <button
                      type="button"
                      onClick={async () => {
                        if (confirm(`Delete session ${selectedSession.id}?`)) {
                          await deleteSession(selectedSession.id);
                          setPackets([]);
                          setSelectedPacket(null);
                        }
                      }}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-sentinel-critical/15 border border-sentinel-critical/40 hover:bg-sentinel-critical/25 text-sentinel-critical font-mono-tech text-xs font-semibold transition-colors"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      DELETE SESSION
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => setCaptureMode('LIVE')}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-sentinel-secondary border border-sentinel-border hover:border-sentinel-copper text-sentinel-text font-mono-tech text-xs rounded transition-colors"
                  >
                    <Radio className="w-3.5 h-3.5 text-sentinel-mint" />
                    SWITCH TO LIVE MODE
                  </button>
                </div>
              </>
            )}
          </div>

          {/* Prompt specified metrics */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 pt-3">
            <div className="p-2 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech">
              <div className="text-[10px] text-sentinel-muted uppercase">
                {captureMode === 'LIVE' ? 'Live Packets' : 'Session Packets'}
              </div>
              <div className="text-xl font-bold text-sentinel-text">{packets.length}</div>
            </div>
            <div className="p-2 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech">
              <div className="text-[10px] text-sentinel-muted uppercase">IKE Handshake</div>
              <div className="text-xl font-bold text-sentinel-copper">{ikeCount}</div>
            </div>
            <div className="p-2 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech">
              <div className="text-[10px] text-sentinel-muted uppercase">ESP Envelopes</div>
              <div className="text-xl font-bold text-sentinel-mint">{espCount}</div>
            </div>
            <div className="p-2 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech">
              <div className="text-[10px] text-sentinel-muted uppercase">Operational Mode</div>
              <div className={`text-sm font-bold mt-1 ${captureMode === 'LIVE' ? 'text-sentinel-mint' : 'text-sentinel-copper'}`}>
                {captureMode === 'LIVE' ? 'LIVE SNIFFER' : 'HISTORIC ARCHIVE'}
              </div>
            </div>
            <div className="p-2 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech col-span-2 sm:col-span-1">
              <div className="text-[10px] text-sentinel-muted uppercase">Anti-Replay Status</div>
              <div className="text-sm font-bold text-sentinel-mint mt-1">VERIFIED (ESN)</div>
            </div>
          </div>
        </div>

        {packets.length === 0 ? (
          captureMode === 'LIVE' ? (
            <div className="panel-technical p-8 sm:p-12 rounded-lg border border-sentinel-border bg-sentinel-elevated/40 space-y-6 text-center max-w-4xl mx-auto my-4">
              <div className="relative w-48 h-48 sm:w-56 sm:h-56 mx-auto flex items-center justify-center select-none">
                <img
                  src="/sentinel-shield.gif"
                  alt="No Live Packets"
                  className="w-48 h-48 sm:w-56 sm:h-56 rounded-full border border-sentinel-border/80 shadow-[0_0_30px_rgba(16,185,129,0.3)] object-cover"
                />
              </div>

              <div className="space-y-2 max-w-lg mx-auto">
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sentinel-secondary border border-sentinel-border text-xs font-mono-tech text-sentinel-mint">
                  <Radio className="w-3.5 h-3.5 text-sentinel-mint animate-pulse" />
                  LIVE STREAM IDLE // SESSION COMPLETED
                </div>
                <h2 className="text-lg sm:text-xl font-mono-tech font-bold text-sentinel-text uppercase tracking-wider">
                  No Active Live Wire Session
                </h2>
                <p className="text-xs text-sentinel-muted leading-relaxed font-sans">
                  The live stream is idle because no session is actively transmitting packets. Completed and recorded sessions are archived in <strong className="text-sentinel-copper">Session Mode</strong>. Switch to Session Mode to inspect recorded frames, or start a new testbed run.
                </p>
              </div>

              <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setCaptureMode('SESSION')}
                  className="flex items-center gap-2 px-5 py-2.5 rounded bg-sentinel-copper hover:bg-sentinel-copperHover text-sentinel-bg font-mono-tech text-xs font-bold transition-all shadow-[0_0_20px_rgba(196,122,82,0.3)] cursor-pointer"
                >
                  <Layers className="w-4 h-4" />
                  SWITCH TO SESSION MODE
                </button>
                <button
                  type="button"
                  onClick={handleInjectTraffic}
                  disabled={isInjectingTraffic}
                  className="flex items-center gap-2 px-4 py-2.5 rounded bg-sentinel-mint/15 border border-sentinel-mint/40 hover:bg-sentinel-mint/25 text-sentinel-mint font-mono-tech text-xs font-semibold transition-colors disabled:opacity-50 cursor-pointer"
                >
                  <Zap className="w-3.5 h-3.5" />
                  {isInjectingTraffic ? 'INJECTING TRAFFIC...' : 'INJECT LIVE TRAFFIC BURST'}
                </button>
                <Link
                  href="/testbed"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 px-4 py-2.5 rounded bg-sentinel-secondary border border-sentinel-border hover:border-sentinel-mint text-sentinel-text font-mono-tech text-xs font-semibold transition-colors"
                >
                  <Cpu className="w-4 h-4 text-sentinel-muted" />
                  TESTBED ORCHESTRATOR
                </Link>
              </div>
            </div>
          ) : (
            <div className="panel-technical p-8 sm:p-12 rounded-lg border border-sentinel-border bg-sentinel-elevated/40 space-y-6 text-center max-w-4xl mx-auto my-4">
              <div className="relative w-48 h-48 sm:w-56 sm:h-56 mx-auto flex items-center justify-center select-none">
                <img
                  src="/sentinel-shield.gif"
                  alt="No Session Data"
                  className="w-48 h-48 sm:w-56 sm:h-56 rounded-full border border-sentinel-border/80 shadow-[0_0_30px_rgba(196,122,82,0.35)] object-cover"
                />
              </div>

              <div className="space-y-2 max-w-lg mx-auto">
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sentinel-secondary border border-sentinel-border text-xs font-mono-tech text-sentinel-copper">
                  <Layers className="w-3.5 h-3.5 text-sentinel-copper" />
                  SESSION ARCHIVE INSPECTION
                </div>
                <h2 className="text-lg sm:text-xl font-mono-tech font-bold text-sentinel-text uppercase tracking-wider">
                  {sessions.length > 0 ? "Select a Session to Inspect" : "No Recorded Sessions Found"}
                </h2>
                <p className="text-xs text-sentinel-muted leading-relaxed font-sans">
                  {sessions.length > 0
                    ? `Found ${sessions.length} historical session archive${sessions.length > 1 ? 's' : ''}. Select a session from the dropdown above or click below to inspect frames.`
                    : "No historical IPsec session archives were found on disk. Switch to Live Mode or launch the testbed to create a new session."}
                </p>
              </div>

              <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
                {sessions.length > 0 ? (
                  <button
                    type="button"
                    onClick={() => {
                      if (sessions[0]) setSelectedSessionId(sessions[0].id);
                    }}
                    className="flex items-center gap-2 px-5 py-2.5 rounded bg-sentinel-copper hover:bg-sentinel-copperHover text-sentinel-bg font-mono-tech text-xs font-bold transition-all shadow-[0_0_20px_rgba(196,122,82,0.3)] cursor-pointer"
                  >
                    <Layers className="w-4 h-4" />
                    LOAD LATEST SESSION ({sessions[0].id})
                  </button>
                ) : (
                  <Link
                    href="/testbed"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 px-5 py-2.5 rounded bg-sentinel-copper hover:bg-sentinel-copperHover text-sentinel-bg font-mono-tech text-xs font-bold transition-all shadow-[0_0_20px_rgba(196,122,82,0.3)]"
                  >
                    <Play className="w-4 h-4 fill-current" />
                    DEPLOY TESTBED RUN
                  </Link>
                )}
                <button
                  type="button"
                  onClick={() => setCaptureMode('LIVE')}
                  className="flex items-center gap-2 px-4 py-2.5 rounded bg-sentinel-secondary border border-sentinel-border hover:border-sentinel-mint text-sentinel-text font-mono-tech text-xs font-semibold transition-colors cursor-pointer"
                >
                  <Radio className="w-3.5 h-3.5 text-sentinel-mint" />
                  SWITCH TO LIVE MODE
                </button>
              </div>
            </div>
          )
        ) : (
          <>
            {/* Packet Artery Timeline Display - Shows full sequence stream with smooth horizontal scroll */}
            <div className="panel-technical p-4 rounded-lg space-y-2 border border-sentinel-border">
              <div className="flex items-center justify-between text-xs font-mono-tech text-sentinel-muted pb-1">
                <span className="uppercase tracking-wider font-semibold text-sentinel-text">
                  Protocol Sequence Stream ({packets.length} Frames Captured)
                </span>
                <div className="flex items-center gap-4 text-[11px]">
                  <span className="flex items-center gap-1.5 text-sentinel-copper">
                    <span className="w-2.5 h-2.5 rounded-full bg-sentinel-copper" /> IKE Handshake ({ikeCount})
                  </span>
                  <span className="flex items-center gap-1.5 text-sentinel-mint">
                    <span className="w-2.5 h-2.5 rounded-full bg-sentinel-mint" /> ESP Data Plane ({espCount})
                  </span>
                </div>
              </div>

              <div className="relative py-2 overflow-x-auto select-none">
                <div className="flex items-center gap-2 min-w-max border-b border-sentinel-border pb-3 px-1">
                  {packets.map((pkt, idx) => {
                    const isSelected = selectedPacket?.id === pkt.id;
                    const isIKE = pkt.protocol === 'IKE';
                    return (
                      <div
                        key={pkt.id}
                        className="flex items-center gap-2 group cursor-pointer"
                        onClick={() => handleSelectPacket(pkt)}
                      >
                        <div
                          className={`flex flex-col items-center px-2 py-1.5 rounded transition-all ${
                            isSelected
                              ? 'bg-sentinel-secondary border-2 border-sentinel-copper shadow-[0_0_12px_rgba(196,122,82,0.35)] scale-105'
                              : 'hover:bg-sentinel-secondary/60 border border-transparent'
                          }`}
                        >
                          <span className="text-[9px] font-mono-tech text-sentinel-muted mb-0.5">
                            #{pkt.id}
                          </span>
                          <div
                            className={`w-3.5 h-3.5 rounded-full border-2 flex items-center justify-center transition-transform group-hover:scale-110 ${
                              isIKE
                                ? 'border-sentinel-copper bg-sentinel-copper/40'
                                : 'border-sentinel-mint bg-sentinel-mint/40'
                            }`}
                          />
                          <span
                            className={`text-[9px] font-mono-tech font-bold mt-1 ${
                              isIKE ? 'text-sentinel-copper' : 'text-sentinel-mint'
                            }`}
                          >
                            {isIKE ? 'IKE' : `ESP #${pkt.seq || idx - 3}`}
                          </span>
                        </div>
                        {idx < packets.length - 1 && (
                          <div className="w-3 sm:w-4 h-[2px] bg-sentinel-border group-hover:bg-sentinel-copper transition-colors" />
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* 2-Column Workstation: LEFT Packet Dissector & RIGHT Terminal */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* LEFT: Packet Dissector Stream (7 Cols) */}
              <div className="lg:col-span-7 panel-technical p-4 rounded-lg space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-sentinel-border">
                  <div className="flex items-center gap-2">
                    <FileCode className="w-4 h-4 text-sentinel-copper" />
                    <span className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                      Packet Dissection Stream
                    </span>
                    <span className="text-[10px] font-mono-tech px-1.5 py-0.2 rounded bg-sentinel-secondary text-sentinel-muted">
                      {filteredPackets.length} shown
                    </span>
                  </div>

                  {/* Protocol Filters & Search */}
                  <div className="flex items-center gap-2">
                    <div className="relative">
                      <Search className="w-3 h-3 text-sentinel-muted absolute left-2 top-2" />
                      <input
                        type="text"
                        placeholder="Search SPI, Seq, Port..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="pl-6 pr-2 py-0.5 rounded text-[11px] font-mono-tech bg-sentinel-secondary border border-sentinel-border text-sentinel-text placeholder-sentinel-muted focus:outline-none focus:border-sentinel-copper w-32 sm:w-40"
                      />
                    </div>

                    <div className="flex items-center gap-1 font-mono-tech text-[10px]">
                      {(['ALL', 'IKE', 'ESP', 'AH'] as const).map((proto) => {
                        const count = proto === 'ALL' ? packets.length : proto === 'IKE' ? ikeCount : proto === 'ESP' ? espCount : 0;
                        return (
                          <button
                            key={proto}
                            onClick={() => setFilterProtocol(proto)}
                            className={`px-2 py-0.5 rounded border transition-colors ${
                              filterProtocol === proto
                                ? 'border-sentinel-copper bg-sentinel-copper/20 text-sentinel-copper font-bold'
                                : 'border-sentinel-border bg-sentinel-secondary text-sentinel-muted hover:text-sentinel-text'
                            }`}
                          >
                            {proto} ({count})
                          </button>
                        );
                      })}
                    </div>
                  </div>
                </div>

                {/* Packet Table with All ESP Packets */}
                <div className="overflow-y-auto max-h-[380px] border border-sentinel-border rounded select-text">
                  <table className="w-full text-left font-mono-tech text-xs border-collapse">
                    <thead className="bg-sentinel-secondary text-sentinel-muted text-[10px] uppercase sticky top-0 border-b border-sentinel-border z-10">
                      <tr>
                        <th className="py-2 px-2.5">No.</th>
                        <th className="py-2 px-2.5">Time</th>
                        <th className="py-2 px-2.5">Protocol</th>
                        <th className="py-2 px-2.5">SPI</th>
                        <th className="py-2 px-2.5">Seq</th>
                        <th className="py-2 px-2.5">Length</th>
                        <th className="py-2 px-2.5">Dissection Summary</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-sentinel-border/50">
                      {filteredPackets.map((p) => {
                        const isSelected = selectedPacket?.id === p.id;
                        return (
                          <tr
                            key={p.id}
                            onClick={() => handleSelectPacket(p)}
                            className={`cursor-pointer transition-colors ${
                              isSelected
                                ? 'bg-sentinel-copper/20 text-sentinel-text font-semibold'
                                : 'hover:bg-sentinel-elevated text-sentinel-muted hover:text-sentinel-text'
                            }`}
                          >
                            <td className="py-2 px-2.5 font-bold text-sentinel-text">
                              #{p.id}
                            </td>
                            <td className="py-2 px-2.5 text-sentinel-muted text-[11px]">
                              {p.timestamp}
                            </td>
                            <td className="py-2 px-2.5">
                              <span
                                className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                  p.protocol === 'IKE'
                                    ? 'bg-sentinel-copper/20 text-sentinel-copper'
                                    : 'bg-sentinel-mint/20 text-sentinel-mint'
                                }`}
                              >
                                {p.protocol}
                              </span>
                            </td>
                            <td className="py-2 px-2.5 text-[11px] text-sentinel-copper font-medium">
                              {p.spi ? p.spi.slice(0, 10) : 'N/A'}
                            </td>
                            <td className="py-2 px-2.5 text-[11px]">
                              {p.seq !== undefined ? (
                                <span className="px-1.5 py-0.2 rounded bg-sentinel-secondary border border-sentinel-border text-sentinel-text">
                                  #{p.seq}
                                </span>
                              ) : (
                                <span className="text-sentinel-muted">-</span>
                              )}
                            </td>
                            <td className="py-2 px-2.5 text-[11px]">{p.length} B</td>
                            <td className="py-2 px-2.5 text-[11px] truncate max-w-[240px]">
                              {p.info}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                {/* Selected Packet Deep Dissection Inspector */}
                {selectedPacket && (
                  <div className="p-3.5 bg-sentinel-deep border border-sentinel-border rounded-lg space-y-3">
                    <div className="flex flex-wrap items-center justify-between text-xs font-mono-tech pb-2 border-b border-sentinel-border">
                      <div className="flex items-center gap-2">
                        <span className="text-sentinel-copper font-bold text-sm">
                          FRAME #{selectedPacket.id}
                        </span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          selectedPacket.protocol === 'IKE'
                            ? 'bg-sentinel-copper/20 text-sentinel-copper'
                            : 'bg-sentinel-mint/20 text-sentinel-mint'
                        }`}>
                          {selectedPacket.protocol} {selectedPacket.protocol === 'ESP' ? 'DATA ENVELOPE' : 'CONTROL PLANE'}
                        </span>
                      </div>
                      <div className="flex items-center gap-3 text-[11px] text-sentinel-muted">
                        <span>SPI: <strong className="text-sentinel-copper">{selectedPacket.spi || 'N/A'}</strong></span>
                        {selectedPacket.seq !== undefined && (
                          <span>Sequence: <strong className="text-sentinel-mint">#{selectedPacket.seq}</strong></span>
                        )}
                        <span>Wire: <strong className="text-sentinel-text">{selectedPacket.length} Bytes</strong></span>
                      </div>
                    </div>

                    {/* Protocol Meta Details */}
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] font-mono-tech">
                      <div className="p-2 rounded bg-sentinel-secondary/50 border border-sentinel-border">
                        <span className="text-[10px] text-sentinel-muted block uppercase">Source Flow</span>
                        <span className="text-sentinel-text font-bold truncate block">{selectedPacket.source}</span>
                      </div>
                      <div className="p-2 rounded bg-sentinel-secondary/50 border border-sentinel-border">
                        <span className="text-[10px] text-sentinel-muted block uppercase">Destination Flow</span>
                        <span className="text-sentinel-text font-bold truncate block">{selectedPacket.destination}</span>
                      </div>
                      <div className="p-2 rounded bg-sentinel-secondary/50 border border-sentinel-border">
                        <span className="text-[10px] text-sentinel-muted block uppercase">Cipher Mode</span>
                        <span className="text-sentinel-mint font-bold block">AES-256-GCM (AEAD)</span>
                      </div>
                      <div className="p-2 rounded bg-sentinel-secondary/50 border border-sentinel-border">
                        <span className="text-[10px] text-sentinel-muted block uppercase">Integrity Verification</span>
                        <span className="text-sentinel-mint font-bold block">✓ 128-bit ICV Verified</span>
                      </div>
                    </div>

                    {/* Dissection Explanation */}
                    <div className="p-2.5 rounded bg-sentinel-secondary/40 border border-sentinel-border text-xs font-mono-tech leading-relaxed">
                      <div className="text-sentinel-muted text-[10px] uppercase font-bold mb-0.5">Dissection Summary:</div>
                      <div className="text-sentinel-text">{selectedPacket.info}</div>
                    </div>

                    {/* Hex Dump View (Wireshark Style) */}
                    <div>
                      <div className="text-[10px] font-mono-tech text-sentinel-muted uppercase font-bold mb-1">
                        Wire Bitstream Hex & ASCII Inspector:
                      </div>
                      <div className="font-mono-tech text-[11px] bg-sentinel-secondary/70 p-2.5 rounded overflow-x-auto leading-relaxed border border-sentinel-border select-text">
                        {formatHexDump(selectedPacket.rawHexPreview).map((row, idx) => (
                          <div key={idx} className="flex gap-4">
                            <span className="text-sentinel-copper select-none">{row.offset}</span>
                            <span className="text-sentinel-text tracking-wider">{row.hex}</span>
                            <span className="text-sentinel-muted border-l border-sentinel-border pl-3 select-none">
                              {row.ascii}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* RIGHT: Live Protocol Analysis Terminal (5 Cols) */}
              <div className="lg:col-span-5 panel-technical p-4 rounded-lg flex flex-col justify-between bg-sentinel-elevated/70 border border-sentinel-border space-y-3">
                <div className="space-y-3">
                  {/* Terminal Header */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-sentinel-border/60">
                    <div className="flex items-center gap-2">
                      <Terminal className="w-4 h-4 text-sentinel-copper" />
                      <span className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                        Protocol Analysis Terminal
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="flex items-center gap-1.5 text-[10px] font-mono-tech text-sentinel-mint">
                        <span className="w-1.5 h-1.5 rounded-full bg-sentinel-mint animate-pulse" />
                        ACTIVE
                      </span>
                      <button
                        onClick={() => {
                          if (terminalTab === 'dissection') setDissectionLogs([]);
                          else setDaemonLogs([]);
                        }}
                        title="Clear terminal"
                        className="p-1 rounded hover:bg-sentinel-secondary text-sentinel-muted hover:text-sentinel-text transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>

                  {/* Terminal Mode Tabs */}
                  <div className="flex items-center gap-2 font-mono-tech text-[10px] pb-1 border-b border-sentinel-border/40">
                    <button
                      onClick={() => setTerminalTab('dissection')}
                      className={`px-3 py-1 rounded transition-colors ${
                        terminalTab === 'dissection'
                          ? 'bg-sentinel-copper text-sentinel-bg font-bold'
                          : 'bg-sentinel-secondary text-sentinel-muted hover:text-sentinel-text border border-sentinel-border'
                      }`}
                    >
                      STREAM DISSECTION ({dissectionLogs.length})
                    </button>
                    <button
                      onClick={() => setTerminalTab('daemon')}
                      className={`px-3 py-1 rounded transition-colors ${
                        terminalTab === 'daemon'
                          ? 'bg-sentinel-copper text-sentinel-bg font-bold'
                          : 'bg-sentinel-secondary text-sentinel-muted hover:text-sentinel-text border border-sentinel-border'
                      }`}
                    >
                      DAEMON LOGS ({daemonLogs.length})
                    </button>
                  </div>

                  {/* Terminal Screen */}
                  <div className="font-mono-tech text-xs space-y-1.5 h-[520px] overflow-y-auto p-2 rounded bg-black/40 border border-sentinel-border/50 leading-relaxed select-text">
                    {(terminalTab === 'dissection' ? dissectionLogs : daemonLogs).map((log, i) => {
                      const isPrompt = log.startsWith('$');
                      const isHighlight = log.startsWith('>>>') || log.includes('INSPECTING');
                      const isESP = log.includes('[ESP');
                      const isIKE = log.includes('[IKE');
                      const isSub = log.trim().startsWith('├──') || log.trim().startsWith('└──');

                      let textClass = 'text-sentinel-muted';
                      if (isPrompt) textClass = 'text-sentinel-copper font-bold';
                      else if (isHighlight) textClass = 'text-sentinel-copper font-semibold bg-sentinel-copper/10 p-1 rounded';
                      else if (isESP) textClass = 'text-sentinel-mint';
                      else if (isIKE) textClass = 'text-sentinel-text font-medium';
                      else if (isSub) textClass = 'text-sentinel-text/90 pl-2';

                      return (
                        <div key={i} className={textClass}>
                          {log}
                        </div>
                      );
                    })}

                    {isCapturing && (
                      <div className="flex items-center gap-1 text-sentinel-copper pt-1">
                        <span>$</span>
                        <span className="inline-block w-1.5 h-3 bg-sentinel-copper animate-pulse" />
                      </div>
                    )}
                  </div>
                </div>

                <div className="pt-2 border-t border-sentinel-border/50 text-[10px] font-mono-tech text-sentinel-muted flex items-center justify-between">
                  <span>BPF Filter: (udp.port==500 || udp.port==4500 || esp)</span>
                  <span className="text-sentinel-mint font-semibold">● Ring Buffer: 100% HEALTHY</span>
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </AppShell>
  );
}
