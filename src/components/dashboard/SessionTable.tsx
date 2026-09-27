'use client';

import React from 'react';
import { useRouter } from 'next/navigation';
import { Session } from '@/types';
import { StatusBadge } from '@/components/common/StatusBadge';
import { ArrowUpRight, Network } from 'lucide-react';

interface SessionTableProps {
  sessions: Session[];
}

export const SessionTable: React.FC<SessionTableProps> = ({ sessions }) => {
  const router = useRouter();

  const formatDhGroup = (dh: string) => {
    if (dh.includes('19')) return 'DH 19';
    if (dh.includes('31')) return 'DH 31';
    if (dh.includes('14')) return 'DH 14';
    if (dh.includes('21')) return 'DH 21';
    if (dh.includes('2')) return 'DH 2';
    return dh.split(' ')[0];
  };

  const formatTraffic = (traffic: string) => {
    if (traffic.toLowerCase().includes('video')) return 'Video (H.264)';
    if (traffic.toLowerCase().includes('web')) return 'Web (HTTPS)';
    if (traffic.toLowerCase().includes('snmp')) return 'SNMP v2c';
    if (traffic.toLowerCase().includes('dns')) return 'DNS Tunnel';
    return traffic;
  };

  return (
    <div className="panel-technical rounded-lg overflow-hidden border border-sentinel-border flex flex-col justify-between h-full">
      {/* Table Header Controls */}
      <div className="p-4 border-b border-sentinel-border flex items-center justify-between bg-sentinel-deep">
        <div className="flex items-center gap-2">
          <Network className="w-4 h-4 text-sentinel-copper" />
          <span className="font-mono-tech text-xs font-semibold text-sentinel-text uppercase tracking-wider">
            Monitored IPsec Tunnel Sessions
          </span>
          <span className="text-[10px] font-mono-tech text-sentinel-muted px-1.5 py-0.5 rounded bg-sentinel-secondary">
            {sessions.length} Active Feeds
          </span>
        </div>
        <button
          onClick={() => router.push('/sessions')}
          className="flex items-center gap-1 text-xs font-mono-tech text-sentinel-copper hover:text-sentinel-copperHover transition-colors"
        >
          View All Sessions <ArrowUpRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Structured Data Table with Horizontal Scroll Isolation */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse min-w-[680px]">
          <thead>
            <tr className="border-b border-sentinel-border bg-sentinel-secondary/50 text-[10px] font-mono-tech uppercase text-sentinel-muted tracking-wider">
              <th className="py-2.5 px-3">Session</th>
              <th className="py-2.5 px-2.5">Source IP</th>
              <th className="py-2.5 px-2.5">Destination IP</th>
              <th className="py-2.5 px-2">IKE</th>
              <th className="py-2.5 px-2">Mode</th>
              <th className="py-2.5 px-2.5">Encryption</th>
              <th className="py-2.5 px-2.5">DH Group</th>
              <th className="py-2.5 px-2">PFS</th>
              <th className="py-2.5 px-2.5">Traffic</th>
              <th className="py-2.5 px-3 text-right">Risk</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-sentinel-border text-xs font-mono-tech">
            {sessions.map((s) => (
              <tr
                key={s.id}
                onClick={() => router.push(`/sessions/${s.id}`)}
                className="hover:bg-sentinel-elevated/80 cursor-pointer transition-colors group"
              >
                <td className="py-3 px-3">
                  <div className="flex items-center gap-1.5 font-bold text-sentinel-text group-hover:text-sentinel-copper transition-colors whitespace-nowrap">
                    <span className="w-1.5 h-1.5 rounded-full bg-sentinel-mint" />
                    {s.id}
                  </div>
                </td>
                <td className="py-3 px-2.5 text-sentinel-muted whitespace-nowrap">{s.source}</td>
                <td className="py-3 px-2.5 text-sentinel-muted whitespace-nowrap">{s.destination}</td>
                <td className="py-3 px-2">
                  <span className="px-1.5 py-0.5 rounded bg-sentinel-secondary text-sentinel-text text-[10px] font-semibold whitespace-nowrap">
                    {s.ikeVersion}
                  </span>
                </td>
                <td className="py-3 px-2 text-sentinel-muted text-[11px] whitespace-nowrap">{s.mode}</td>
                <td className="py-3 px-2.5 text-sentinel-text font-medium whitespace-nowrap">
                  {s.encryption}
                </td>
                <td className="py-3 px-2.5 text-sentinel-copper whitespace-nowrap font-medium">
                  {formatDhGroup(s.dhGroup)}
                </td>
                <td className="py-3 px-2">
                  {s.pfs ? (
                    <span className="text-sentinel-mint font-bold text-[11px]">ON</span>
                  ) : (
                    <span className="text-sentinel-critical font-bold text-[11px]">OFF</span>
                  )}
                </td>
                <td className="py-3 px-2.5 text-sentinel-text whitespace-nowrap text-[11px]">
                  {formatTraffic(s.trafficType)}
                </td>
                <td className="py-3 px-3 text-right whitespace-nowrap">
                  <StatusBadge status={s.risk} size="sm" />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="p-2.5 border-t border-sentinel-border bg-sentinel-secondary/20 text-[10px] font-mono-tech text-sentinel-muted flex items-center justify-between">
        <span>Click any row to open technical session dissection</span>
        <span className="text-sentinel-copper font-medium">4 Active Feeds</span>
      </div>
    </div>
  );
};
