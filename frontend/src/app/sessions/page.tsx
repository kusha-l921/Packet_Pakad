'use client';

import React, { useState, useEffect } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import { fetchSessions } from '@/lib/api/sessions';
import { fetchTestbedStatus } from '@/lib/api/testbed';
import { StatusBadge } from '@/components/common/StatusBadge';
import { NoDataState } from '@/components/common/NoDataState';
import { SessionSelector } from '@/components/common/SessionSelector';
import { useSession } from '@/context/SessionContext';
import { Session } from '@/types';
import { useRouter } from 'next/navigation';
import {
  Network,
  Search,
  Filter,
  ArrowRight,
  Shield,
  Layers,
  ArrowUpRight,
  Trash2,
} from 'lucide-react';
import Link from 'next/link';

export default function SessionsPage() {
  const router = useRouter();
  const { setSelectedSessionId, deleteSession, deleteAllSessions } = useSession();
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedRisk, setSelectedRisk] = useState<string>('ALL');
  const [sessions, setSessions] = useState<Session[]>([]);
  const [testbedStatus, setTestbedStatus] = useState<any>(null);

  useEffect(() => {
    const load = () => {
      fetchSessions()
        .then((data) => {
          setSessions(Array.isArray(data) ? data : []);
        })
        .catch(() => {
          setSessions([]);
        });

      fetchTestbedStatus()
        .then(setTestbedStatus)
        .catch(() => {});
    };

    load();
    const interval = setInterval(load, 3000);
    return () => clearInterval(interval);
  }, []);

  const hasData = sessions.length > 0;

  const filteredSessions = sessions.filter((s) => {
    const matchesSearch =
      s.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.source.includes(searchQuery) ||
      s.destination.includes(searchQuery) ||
      s.encryption.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesRisk = selectedRisk === 'ALL' || s.risk === selectedRisk;
    return matchesSearch && matchesRisk;
  });

  return (
    <AppShell>
      <div className="space-y-6 max-w-7xl mx-auto">
        {/* Page Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-sentinel-border">
          <div>
            <div className="flex items-center gap-2">
              <Network className="w-5 h-5 text-sentinel-copper" />
              <h1 className="font-mono-tech text-base md:text-lg font-bold tracking-wider text-sentinel-text uppercase">
                Canonical Session Explorer
              </h1>
            </div>
            <p className="text-xs text-sentinel-muted mt-0.5">
              Reconstructed IKEv1/IKEv2 session states, Security Association (SA) pairs, and in-flight tunnel telemetry.
            </p>
          </div>

          <div className="flex items-center gap-3 flex-wrap">
            <SessionSelector />
            <div className="flex items-center gap-2 font-mono-tech text-xs">
              <span className="text-sentinel-muted">RECONSTRUCTED:</span>
              <span className="px-2 py-0.5 rounded bg-sentinel-copper/15 border border-sentinel-copper/40 text-sentinel-copper font-bold">
                {sessions.length} Tunnels
              </span>
            </div>
            {sessions.length > 0 && (
              <button
                type="button"
                onClick={async () => {
                  if (confirm(`Are you sure you want to delete all ${sessions.length} recorded sessions?`)) {
                    await deleteAllSessions();
                    setSessions([]);
                  }
                }}
                className="flex items-center gap-1.5 px-3 py-1 rounded bg-sentinel-critical/15 border border-sentinel-critical/40 hover:bg-sentinel-critical/25 text-sentinel-critical font-mono-tech text-xs font-semibold transition-colors"
              >
                <Trash2 className="w-3.5 h-3.5" />
                Delete All Sessions
              </button>
            )}
          </div>
        </div>

        {!hasData ? (
          <NoDataState
            title="NO SESSIONS TO PROCESS"
            description="No active or historical IPsec sessions have been recorded. Deploy the strongSwan testbed to establish encrypted Child SAs."
          />
        ) : (
          <>

        {/* Filters & Search Toolbar */}
        <div className="panel-technical p-4 rounded-lg flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 text-sentinel-muted absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by session ID, IP address, or cipher..."
              className="w-full bg-sentinel-secondary pl-9 pr-4 py-2 rounded border border-sentinel-border text-xs text-sentinel-text placeholder:text-sentinel-muted focus:outline-none focus:border-sentinel-copper font-mono-tech"
            />
          </div>

          <div className="flex items-center gap-2 font-mono-tech text-xs">
            <span className="text-sentinel-muted text-[11px] uppercase">Risk:</span>
            {(['ALL', 'LOW', 'MEDIUM', 'CRITICAL'] as const).map((risk) => (
              <button
                key={risk}
                onClick={() => setSelectedRisk(risk)}
                className={`px-2.5 py-1 rounded border transition-colors ${
                  selectedRisk === risk
                    ? 'border-sentinel-copper bg-sentinel-copper/20 text-sentinel-copper font-bold'
                    : 'border-sentinel-border bg-sentinel-secondary text-sentinel-muted hover:text-sentinel-text'
                }`}
              >
                {risk}
              </button>
            ))}
          </div>
        </div>

        {/* Data Table */}
        <div className="panel-technical rounded-lg overflow-hidden border border-sentinel-border">
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono-tech text-xs border-collapse min-w-[850px]">
              <thead className="bg-sentinel-secondary/60 text-sentinel-muted text-[10px] uppercase border-b border-sentinel-border tracking-wider">
                <tr>
                  <th className="py-3 px-4">Session ID</th>
                  <th className="py-3 px-4">Endpoints (Src → Dst)</th>
                  <th className="py-3 px-4">Protocol</th>
                  <th className="py-3 px-4">Mode</th>
                  <th className="py-3 px-4">Symmetric Cipher</th>
                  <th className="py-3 px-4">Diffie-Hellman</th>
                  <th className="py-3 px-4">PFS</th>
                  <th className="py-3 px-4">Traffic Type</th>
                  <th className="py-3 px-4">Risk Rating</th>
                  <th className="py-3 px-4 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sentinel-border">
                {filteredSessions.map((s) => (
                  <tr
                    key={s.id}
                    onClick={() => {
                      setSelectedSessionId(s.id);
                      router.push(`/sessions/${s.id}`);
                    }}
                    className="hover:bg-sentinel-elevated cursor-pointer transition-colors group"
                  >
                    <td className="py-3.5 px-4">
                      <div className="font-bold text-sentinel-text group-hover:text-sentinel-copper transition-colors flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-sentinel-mint" />
                        {s.id}
                      </div>
                      <div className="text-[10px] text-sentinel-muted">
                        SPI: {s.spiIn}
                      </div>
                    </td>
                    <td className="py-3.5 px-4 text-sentinel-muted">
                      <div>{s.source}</div>
                      <div className="text-[10px] text-sentinel-muted/60">→ {s.destination}</div>
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="px-1.5 py-0.5 rounded bg-sentinel-secondary text-sentinel-text font-semibold">
                        {s.ikeVersion}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-sentinel-muted">{s.mode}</td>
                    <td className="py-3.5 px-4 text-sentinel-text font-medium">
                      {s.encryption}
                    </td>
                    <td className="py-3.5 px-4 text-sentinel-copper font-medium">
                      {s.dhGroup.includes('19')
                        ? 'DH 19 (P-256)'
                        : s.dhGroup.includes('31')
                        ? 'DH 31 (X25519)'
                        : s.dhGroup.includes('14')
                        ? 'DH 14 (2048)'
                        : s.dhGroup.includes('2')
                        ? 'DH 2 (1024)'
                        : s.dhGroup}
                    </td>
                    <td className="py-3.5 px-4">
                      {s.pfs ? (
                        <span className="text-sentinel-mint font-bold">ON</span>
                      ) : (
                        <span className="text-sentinel-critical font-bold">OFF</span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 text-sentinel-text">{s.trafficType}</td>
                    <td className="py-3.5 px-4">
                      <StatusBadge status={s.risk} size="sm" />
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <div className="flex items-center justify-end gap-2.5">
                        <span className="inline-flex items-center gap-1 text-sentinel-copper group-hover:underline">
                          Dissect <ArrowRight className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
                        </span>
                        <button
                          type="button"
                          title="Delete session"
                          onClick={async (e) => {
                            e.stopPropagation();
                            if (confirm(`Delete session ${s.id}?`)) {
                              await deleteSession(s.id);
                              setSessions((prev) => prev.filter((item) => item.id !== s.id));
                            }
                          }}
                          className="p-1 rounded text-sentinel-muted hover:text-sentinel-critical hover:bg-sentinel-critical/15 transition-colors"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
          </div>
        </>
      )}
    </div>
  </AppShell>
);
}
