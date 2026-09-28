'use client';

import React, { useState } from 'react';
import { Radio, Download, Filter, Terminal, Play, Pause } from 'lucide-react';

export default function PacketCapturePage() {
  const [capturing, setCapturing] = useState(true);

  const mockPackets = [
    { no: 18419, time: '04:18:21.102', src: '10.0.1.12:4500', dst: '10.0.2.20:4500', proto: 'ESP', spi: '0x9b4a2e1f', len: 1420, info: 'ESP Encap Frame (RFC 4303) Seq=18419' },
    { no: 18420, time: '04:18:21.135', src: '10.0.1.12:4500', dst: '10.0.2.20:4500', proto: 'ESP', spi: '0x9b4a2e1f', len: 1420, info: 'ESP Encap Frame (RFC 4303) Seq=18420' },
    { no: 18421, time: '04:18:21.168', src: '10.0.2.20:4500', dst: '10.0.1.12:4500', proto: 'ESP', spi: '0x3c8d197a', len: 180, info: 'ESP RTCP Receiver Feedback Seq=9421' },
    { no: 18422, time: '04:18:21.829', src: '10.0.1.12:4500', dst: '10.0.2.20:4500', proto: 'IKEv2', spi: '0x9b4a2e1f', len: 320, info: 'CREATE_CHILD_SA Rekey Request (Missing KEs)' },
    { no: 18423, time: '04:18:21.845', src: '10.0.2.20:4500', dst: '10.0.1.12:4500', proto: 'IKEv2', spi: '0x3c8d197a', len: 280, info: 'CREATE_CHILD_SA Rekey Response (Accepted)' },
  ];

  return (
    <div className="space-y-6 font-mono text-xs">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-sentinel-border">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Radio className="w-4 h-4 text-sentinel-copper" />
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-sentinel-text uppercase">
              LIVE PACKET CAPTURE & DISSECTION STREAM
            </h1>
          </div>
          <p className="text-xs text-sentinel-text-muted">
            Zero-copy packet ingress on interface eth0 (UDP 500 / 4500 / Proto 50).
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setCapturing(!capturing)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded font-bold border transition-colors ${
              capturing
                ? 'border-sentinel-warning bg-sentinel-warning/15 text-sentinel-warning'
                : 'border-sentinel-mint bg-sentinel-mint/15 text-sentinel-mint'
            }`}
          >
            {capturing ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            <span>{capturing ? 'Pause Stream' : 'Resume Ingest'}</span>
          </button>
          <button className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-sentinel-border bg-[#151719] text-sentinel-text hover:border-sentinel-copper transition-colors">
            <Download className="w-3.5 h-3.5" />
            <span>Download PCAP</span>
          </button>
        </div>
      </div>

      {/* Live Packets Table */}
      <div className="rounded-xl border border-sentinel-border bg-[#101214] overflow-hidden">
        <div className="p-3 bg-[#151719] border-b border-sentinel-border flex items-center justify-between text-[11px] text-sentinel-text-muted">
          <span>INGRESS BUFFER: 65,421 PACKETS CAPTURED</span>
          <span className="text-sentinel-mint">FILTER: proto ipsec or udp port 500 or udp port 4500</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-sentinel-border text-[10px] text-sentinel-text-muted uppercase">
                <th className="py-2.5 px-3">NO.</th>
                <th className="py-2.5 px-3">TIME</th>
                <th className="py-2.5 px-3">SOURCE</th>
                <th className="py-2.5 px-3">DESTINATION</th>
                <th className="py-2.5 px-3">PROTO</th>
                <th className="py-2.5 px-3">SPI</th>
                <th className="py-2.5 px-3">LEN</th>
                <th className="py-2.5 px-3">INFO</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-sentinel-border/50 text-[11px]">
              {mockPackets.map((pkt) => (
                <tr key={pkt.no} className="hover:bg-[#151719] transition-colors">
                  <td className="py-2 px-3 text-sentinel-text-muted">{pkt.no}</td>
                  <td className="py-2 px-3 text-sentinel-text-muted">{pkt.time}</td>
                  <td className="py-2 px-3 text-sentinel-text font-bold">{pkt.src}</td>
                  <td className="py-2 px-3 text-sentinel-text">{pkt.dst}</td>
                  <td className="py-2 px-3">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${pkt.proto === 'IKEv2' ? 'bg-sentinel-copper/20 text-sentinel-copper' : 'bg-sentinel-mint/20 text-sentinel-mint'}`}>
                      {pkt.proto}
                    </span>
                  </td>
                  <td className="py-2 px-3 text-sentinel-copper font-mono">{pkt.spi}</td>
                  <td className="py-2 px-3 text-sentinel-text-muted">{pkt.len} B</td>
                  <td className="py-2 px-3 text-sentinel-text">{pkt.info}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
