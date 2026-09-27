'use client';

import React, { useState, useEffect } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import { motion, AnimatePresence } from 'framer-motion';
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
} from 'lucide-react';
import { Packet, ProtocolType } from '@/types';

const initialPackets: Packet[] = [
  {
    id: 1,
    timestamp: '14:32:18.102',
    source: '10.0.1.12:500',
    destination: '10.0.2.20:500',
    protocol: 'IKE',
    info: 'IKE_SA_INIT Exchange (Initiator Request, SA, KE: Grp 19, Nonce)',
    length: 312,
    spi: '0x3c8d197a00000000',
    rawHexPreview: '3c 8d 19 7a 00 00 00 00 22 20 02 00 00 00 00 00 00 00 01 0c 0a 00 01 0c 00 00 00 28 00 00 00 24 01 01 00 03 03 00 00 0c 01 00 00 14',
  },
  {
    id: 2,
    timestamp: '14:32:18.188',
    source: '10.0.2.20:500',
    destination: '10.0.1.12:500',
    protocol: 'IKE',
    info: 'IKE_SA_INIT Response (Responder SA, KE, Nonce, NAT-D)',
    length: 348,
    spi: '0x3c8d197a9b4a2e1f',
    rawHexPreview: '3c 8d 19 7a 9b 4a 2e 1f 22 20 02 20 00 00 00 00 00 00 01 24 0a 00 02 14 00 00 00 28 00 00 00 24 01 01 00 03 03 00 00 0c 01 00 00 14',
  },
  {
    id: 3,
    timestamp: '14:32:18.420',
    source: '10.0.1.12:4500',
    destination: '10.0.2.20:4500',
    protocol: 'IKE',
    info: 'IKE_AUTH Request (Encrypted: IDi, CERT, AUTH, SA: AES_256_GCM)',
    length: 1240,
    spi: '0x3c8d197a9b4a2e1f',
    rawHexPreview: '3c 8d 19 7a 9b 4a 2e 1f 2e 20 02 20 00 00 00 01 00 00 04 d8 00 00 00 00 46 b8 12 e9 9a 11 02 c8 92 10 4f f1 2a 3b 4c 5d 6e 7f 80 91',
  },
  {
    id: 4,
    timestamp: '14:32:18.512',
    source: '10.0.2.20:4500',
    destination: '10.0.1.12:4500',
    protocol: 'IKE',
    info: 'IKE_AUTH Response (Encrypted: IDr, AUTH, SA, Child-SA Established)',
    length: 980,
    spi: '0x3c8d197a9b4a2e1f',
    rawHexPreview: '3c 8d 19 7a 9b 4a 2e 1f 2e 20 02 20 00 00 00 01 00 00 03 d4 00 00 00 00 fa 31 90 bb 12 77 aa 99 22 11 00 55 44 33 22 11 0a 0b 0c 0d',
  },
  {
    id: 5,
    timestamp: '14:32:19.004',
    source: '10.0.1.12',
    destination: '10.0.2.20',
    protocol: 'ESP',
    info: 'ESP Payload (SPI: 0x9b4a2e1f, Seq: 1, 1420 bytes encrypted)',
    length: 1420,
    spi: '0x9b4a2e1f',
    seq: 1,
    rawHexPreview: '9b 4a 2e 1f 00 00 00 01 5a 89 c2 44 11 90 ef 87 23 45 67 89 ab cd ef 01 23 45 67 89 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff',
  },
  {
    id: 6,
    timestamp: '14:32:19.037',
    source: '10.0.1.12',
    destination: '10.0.2.20',
    protocol: 'ESP',
    info: 'ESP Payload (SPI: 0x9b4a2e1f, Seq: 2, 1420 bytes encrypted)',
    length: 1420,
    spi: '0x9b4a2e1f',
    seq: 2,
    rawHexPreview: '9b 4a 2e 1f 00 00 00 02 bc 41 89 aa 22 11 00 fa d4 e1 98 22 71 82 93 a4 b5 c6 d7 e8 f9 0a 1b 2c 3d 4e 5f 60 71 82 93 a4 b5 c6 d7 e8',
  },
  {
    id: 7,
    timestamp: '14:32:20.015',
    source: '10.0.1.12:4500',
    destination: '10.0.2.20:4500',
    protocol: 'IKE',
    info: 'CREATE_CHILD_SA (Rekey Proposal - Warning: Omitted KE payload)',
    length: 460,
    spi: '0x3c8d197a9b4a2e1f',
    rawHexPreview: '3c 8d 19 7a 9b 4a 2e 1f 24 20 02 20 00 00 00 02 00 00 01 cc 00 00 00 00 c1 d2 e3 f4 a1 b2 c3 d4 e5 f6 a7 b8 c9 d0 e1 f2 11 22 33 44',
  },
];

export default function PacketCapturePage() {
  const [packets, setPackets] = useState<Packet[]>(initialPackets);
  const [isCapturing, setIsCapturing] = useState<boolean>(true);
  const [selectedPacket, setSelectedPacket] = useState<Packet>(initialPackets[0]);
  const [filterProtocol, setFilterProtocol] = useState<'ALL' | 'IKE' | 'ESP' | 'AH'>('ALL');
  const [terminalLogs, setTerminalLogs] = useState<string[]>([
    '$ ipsec-analyzer --live --interface eth0',
    '[14:32:18] Promiscuous capture active on eth0 (filter: udp port 500 or udp port 4500 or proto 50)',
    '[14:32:18] IKEv2 detected (RFC 7296)',
    '[14:32:19] Session reconstructed: IPSEC-00421',
    '[14:32:20] AES-256-GCM identified with 128-bit ICV',
    '[14:32:20] DH Group 19 (ECP-256) accepted',
    '[14:32:21] PFS enabled for initial exchange',
    '[14:32:22] Traffic classifier running: RTP/Video pattern observed',
  ]);

  // Simulate incoming live packets
  useEffect(() => {
    if (!isCapturing) return;

    const interval = setInterval(() => {
      const nextId = packets.length + 1;
      const isESP = Math.random() > 0.2;
      const now = new Date();
      const timeStr = `${now.toTimeString().split(' ')[0]}.${String(now.getMilliseconds()).padStart(3, '0')}`;

      const newPkt: Packet = isESP
        ? {
            id: nextId,
            timestamp: timeStr,
            source: '10.0.1.12',
            destination: '10.0.2.20',
            protocol: 'ESP',
            info: `ESP Payload (SPI: 0x9b4a2e1f, Seq: ${nextId + 100}, 1420 bytes)`,
            length: 1420,
            spi: '0x9b4a2e1f',
            seq: nextId + 100,
            rawHexPreview: '9b 4a 2e 1f ' + Array.from({ length: 16 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(' '),
          }
        : {
            id: nextId,
            timestamp: timeStr,
            source: '10.0.2.20:4500',
            destination: '10.0.1.12:4500',
            protocol: 'IKE',
            info: 'INFORMATIONAL Keepalive (DPD ACK / Sequence check)',
            length: 128,
            spi: '0x3c8d197a9b4a2e1f',
            rawHexPreview: '3c 8d 19 7a 9b 4a 2e 1f 25 20 02 20 00 00 00 03 00 00 00 80 ' + Array.from({ length: 8 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(' '),
          };

      setPackets((prev) => [newPkt, ...prev.slice(0, 49)]);

      if (!isESP) {
        setTerminalLogs((prev) => [
          ...prev,
          `[${timeStr}] Dissected IKE packet #${nextId} on port 4500 (SPI: 0x9b4a2e1f)`,
        ]);
      }
    }, 2400);

    return () => clearInterval(interval);
  }, [isCapturing, packets.length]);

  const filteredPackets = packets.filter(
    (p) => filterProtocol === 'ALL' || p.protocol === filterProtocol
  );

  return (
    <AppShell>
      <div className="space-y-6 max-w-7xl mx-auto">
        {/* Top Metrics Strip */}
        <div className="panel-technical rounded-lg p-4 border border-sentinel-border">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-3 border-b border-sentinel-border">
            <div className="flex items-center gap-2">
              <Radio className="w-5 h-5 text-sentinel-copper" />
              <div>
                <h1 className="font-mono-tech text-base font-bold tracking-wider text-sentinel-text uppercase">
                  Packet Capture & Live Ingestion
                </h1>
                <div className="text-[11px] text-sentinel-muted">
                  Multi-Modal Bitstream Ingestion • Ring Buffer Capacity: 100,000 Frames
                </div>
              </div>
            </div>

            {/* Ingestion Controls */}
            <div className="flex items-center gap-2">
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
                    STOP CAPTURE
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5 fill-current" />
                    RESUME CAPTURE
                  </>
                )}
              </button>

              <button
                onClick={() => {
                  setTerminalLogs((prev) => [
                    ...prev,
                    `[${new Date().toISOString().split('T')[1].slice(0, 8)}] Ingesting PCAP bitstream ntro_border_sample.pcapng... Done.`,
                  ]);
                }}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-sentinel-copper text-sentinel-bg font-mono-tech text-xs font-semibold rounded hover:bg-sentinel-copperHover transition-colors"
              >
                <Upload className="w-3.5 h-3.5" />
                UPLOAD PCAP
              </button>
            </div>
          </div>

          {/* Prompt specified metrics */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 pt-3">
            <div className="p-2 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech">
              <div className="text-[10px] text-sentinel-muted uppercase">Packets</div>
              <div className="text-xl font-bold text-sentinel-text">18,421</div>
            </div>
            <div className="p-2 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech">
              <div className="text-[10px] text-sentinel-muted uppercase">IKE Frames</div>
              <div className="text-xl font-bold text-sentinel-copper">42</div>
            </div>
            <div className="p-2 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech">
              <div className="text-[10px] text-sentinel-muted uppercase">ESP Envelopes</div>
              <div className="text-xl font-bold text-sentinel-mint">18,379</div>
            </div>
            <div className="p-2 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech">
              <div className="text-[10px] text-sentinel-muted uppercase">Active Flows</div>
              <div className="text-xl font-bold text-sentinel-text">24</div>
            </div>
            <div className="p-2 rounded bg-sentinel-secondary/40 border border-sentinel-border font-mono-tech col-span-2 sm:col-span-1">
              <div className="text-[10px] text-sentinel-muted uppercase">Canonical Sessions</div>
              <div className="text-xl font-bold text-sentinel-text">8</div>
            </div>
          </div>
        </div>

        {/* Packet Artery Timeline Display (●────●──────●───●────●──────●) */}
        <div className="panel-technical p-4 rounded-lg space-y-2 border border-sentinel-border">
          <div className="flex items-center justify-between text-xs font-mono-tech text-sentinel-muted">
            <span className="uppercase tracking-wider">Protocol Sequence Stream</span>
            <div className="flex items-center gap-3">
              <span className="flex items-center gap-1 text-sentinel-copper">
                <span className="w-2 h-2 rounded-full bg-sentinel-copper" /> IKE Handshake
              </span>
              <span className="flex items-center gap-1 text-sentinel-mint">
                <span className="w-2 h-2 rounded-full bg-sentinel-mint" /> ESP Enclosed
              </span>
            </div>
          </div>

          <div className="relative py-2 overflow-x-auto">
            <div className="flex items-center gap-4 min-w-[700px] border-b border-sentinel-border pb-3">
              {packets.slice(0, 10).map((pkt, idx) => (
                <div key={pkt.id} className="flex items-center gap-3 group cursor-pointer" onClick={() => setSelectedPacket(pkt)}>
                  <div className="flex flex-col items-center">
                    <span className="text-[9px] font-mono-tech text-sentinel-muted mb-1">
                      #{pkt.id}
                    </span>
                    <div
                      className={`w-3.5 h-3.5 rounded-full border-2 transition-transform group-hover:scale-125 ${
                        pkt.protocol === 'IKE'
                          ? 'border-sentinel-copper bg-sentinel-copper/30'
                          : 'border-sentinel-mint bg-sentinel-mint/30'
                      }`}
                    />
                    <span
                      className={`text-[9px] font-mono-tech font-bold mt-1 ${
                        pkt.protocol === 'IKE' ? 'text-sentinel-copper' : 'text-sentinel-mint'
                      }`}
                    >
                      {pkt.protocol}
                    </span>
                  </div>
                  {idx < 9 && (
                    <div className="w-8 h-[2px] bg-sentinel-border group-hover:bg-sentinel-copper transition-colors" />
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* 2-Column Workstation: LEFT Packet Dissector & RIGHT Terminal */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* LEFT: Packet Dissector Stream (7 Cols) */}
          <div className="lg:col-span-7 panel-technical p-4 rounded-lg space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-sentinel-border">
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-sentinel-copper" />
                <span className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                  Packet Dissection Stream
                </span>
              </div>

              {/* Protocol Filters */}
              <div className="flex items-center gap-1 font-mono-tech text-[10px]">
                {(['ALL', 'IKE', 'ESP', 'AH'] as const).map((proto) => (
                  <button
                    key={proto}
                    onClick={() => setFilterProtocol(proto)}
                    className={`px-2 py-0.5 rounded border transition-colors ${
                      filterProtocol === proto
                        ? 'border-sentinel-copper bg-sentinel-copper/20 text-sentinel-copper font-bold'
                        : 'border-sentinel-border bg-sentinel-secondary text-sentinel-muted hover:text-sentinel-text'
                    }`}
                  >
                    {proto}
                  </button>
                ))}
              </div>
            </div>

            {/* Packet Table */}
            <div className="overflow-y-auto max-h-80 border border-sentinel-border rounded">
              <table className="w-full text-left font-mono-tech text-xs border-collapse">
                <thead className="bg-sentinel-secondary/60 text-sentinel-muted text-[10px] uppercase sticky top-0 border-b border-sentinel-border">
                  <tr>
                    <th className="py-2 px-2.5">No.</th>
                    <th className="py-2 px-2.5">Time</th>
                    <th className="py-2 px-2.5">Protocol</th>
                    <th className="py-2 px-2.5">Length</th>
                    <th className="py-2 px-2.5">Info</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-sentinel-border/50">
                  {filteredPackets.map((p) => {
                    const isSelected = selectedPacket.id === p.id;
                    return (
                      <tr
                        key={p.id}
                        onClick={() => setSelectedPacket(p)}
                        className={`cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-sentinel-copper/15 text-sentinel-text'
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
                        <td className="py-2 px-2.5 text-[11px]">{p.length} B</td>
                        <td className="py-2 px-2.5 text-[11px] truncate max-w-[280px]">
                          {p.info}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Selected Packet Dissection Hex View */}
            {selectedPacket && (
              <div className="p-3 bg-sentinel-deep border border-sentinel-border rounded space-y-2">
                <div className="flex items-center justify-between text-xs font-mono-tech pb-1 border-b border-sentinel-border/50">
                  <span className="text-sentinel-copper font-semibold">
                    DISSECTOR INSPECTOR: FRAME #{selectedPacket.id} ({selectedPacket.protocol})
                  </span>
                  <span className="text-sentinel-muted text-[10px]">
                    SPI: {selectedPacket.spi || 'N/A'}
                  </span>
                </div>
                <div className="font-mono-tech text-[11px] text-sentinel-muted bg-sentinel-secondary/60 p-2.5 rounded overflow-x-auto leading-relaxed border border-sentinel-border/40">
                  <div className="text-sentinel-copper/70 pb-1">
                    0000: {selectedPacket.rawHexPreview || 'N/A'}
                  </div>
                  <div className="text-sentinel-muted/80">
                    Source: {selectedPacket.source} → Destination: {selectedPacket.destination}
                  </div>
                  <div className="text-sentinel-text pt-0.5">
                    Payload Details: {selectedPacket.info}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* RIGHT: Live Analysis Terminal (5 Cols) */}
          <div className="lg:col-span-5 panel-technical p-4 rounded-lg flex flex-col justify-between bg-sentinel-elevated/70">
            <div className="space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-sentinel-border/60">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-sentinel-copper" />
                  <span className="font-mono-tech text-xs font-bold uppercase tracking-wider text-sentinel-text">
                    Protocol Analysis Terminal
                  </span>
                </div>
                <span className="flex items-center gap-1.5 text-[10px] font-mono-tech text-sentinel-mint">
                  <span className="w-1.5 h-1.5 rounded-full bg-sentinel-mint animate-pulse" />
                  DAEMON RUNNING
                </span>
              </div>

              {/* Terminal Screen with subtle prompt style */}
              <div className="font-mono-tech text-xs space-y-2 h-[420px] overflow-y-auto p-1 leading-relaxed">
                {terminalLogs.map((log, i) => (
                  <div key={i} className="text-sentinel-muted">
                    {log.startsWith('$') ? (
                      <span className="text-sentinel-copper font-bold">{log}</span>
                    ) : (
                      <span>{log}</span>
                    )}
                  </div>
                ))}
                {isCapturing && (
                  <div className="flex items-center gap-1 text-sentinel-copper">
                    <span>$</span>
                    <span className="inline-block w-1.5 h-3 bg-sentinel-copper animate-blink" />
                  </div>
                )}
              </div>
            </div>

            <div className="pt-2 border-t border-sentinel-border/50 text-[10px] font-mono-tech text-sentinel-muted flex items-center justify-between">
              <span>Filter: udp.port==500 || esp</span>
              <span>Buffer: 100% OK</span>
            </div>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
