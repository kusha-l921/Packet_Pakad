'use client';

import React, { useState, useRef, useEffect } from 'react';
import { useSession } from '@/context/SessionContext';
import { Network, ChevronDown, Check, Search, Radio, Clock, Shield, Trash2, Plus } from 'lucide-react';
import Link from 'next/link';

interface SessionSelectorProps {
  className?: string;
  compact?: boolean;
}

export const SessionSelector: React.FC<SessionSelectorProps> = ({
  className = '',
  compact = false,
}) => {
  const { sessions, selectedSessionId, selectedSession, setSelectedSessionId, deleteSession, deleteAllSessions } = useSession();
  const [isOpen, setIsOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Close dropdown on click outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const filteredSessions = sessions.filter((s) => {
    const term = searchTerm.toLowerCase();
    return (
      s.id.toLowerCase().includes(term) ||
      (s.rawId && s.rawId.toLowerCase().includes(term)) ||
      s.encryption.toLowerCase().includes(term) ||
      s.mode.toLowerCase().includes(term) ||
      s.source.includes(term) ||
      s.destination.includes(term)
    );
  });

  const activeId = selectedSession?.id || selectedSessionId || (sessions.length > 0 ? sessions[0].id : 'STANDBY');
  const isActive = selectedSession?.status === 'ACTIVE';

  return (
    <div className={`relative inline-block text-left font-mono-tech ${className}`} ref={dropdownRef}>
      {/* Trigger Button */}
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className={`flex items-center gap-2 rounded border transition-all text-xs focus:outline-none ${
          isOpen
            ? 'border-sentinel-copper bg-sentinel-copper/10 text-sentinel-copper shadow-sm'
            : 'border-sentinel-border bg-sentinel-secondary/80 hover:border-sentinel-copper/70 text-sentinel-text hover:bg-sentinel-secondary'
        } ${compact ? 'px-2.5 py-1 text-[11px]' : 'px-3 py-1.5'}`}
      >
        <div className="flex items-center gap-1.5 text-sentinel-copper">
          <Network className="w-3.5 h-3.5" />
          <span className="text-[10px] text-sentinel-muted uppercase font-semibold">SESSION:</span>
        </div>

        <span className="font-bold tracking-wide text-sentinel-text">{activeId}</span>

        {selectedSession && (
          <span className="hidden sm:inline-block text-[10px] px-1.5 py-0.2 rounded bg-sentinel-elevated border border-sentinel-border text-sentinel-muted">
            {selectedSession.mode} • {selectedSession.encryption}
          </span>
        )}

        <span
          className={`w-2 h-2 rounded-full ${
            isActive ? 'bg-sentinel-mint animate-pulse' : 'bg-sentinel-muted/60'
          }`}
          title={isActive ? 'Active Tunnel' : 'Recorded Session'}
        />

        <ChevronDown
          className={`w-3.5 h-3.5 text-sentinel-muted transition-transform duration-200 ${
            isOpen ? 'rotate-180 text-sentinel-copper' : ''
          }`}
        />
      </button>

      {/* Dropdown Menu */}
      {isOpen && (
        <div className="absolute left-0 sm:right-0 sm:left-auto mt-1.5 w-80 sm:w-96 rounded-lg bg-sentinel-deep border border-sentinel-border shadow-2xl z-50 overflow-hidden divide-y divide-sentinel-border/60 animate-in fade-in zoom-in-95 duration-100">
          {/* Header & Filter */}
          <div className="p-2.5 bg-sentinel-secondary/60 space-y-2">
            <div className="flex items-center justify-between text-[11px]">
              <span className="font-bold text-sentinel-text uppercase flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5 text-sentinel-copper" />
                Select Analysis Session
              </span>
              <span className="text-[10px] text-sentinel-muted">
                {sessions.length} Available
              </span>
            </div>

            <div className="relative">
              <Search className="w-3.5 h-3.5 text-sentinel-muted absolute left-2.5 top-2" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Filter by ID, SPI, cipher, mode..."
                className="w-full pl-8 pr-2.5 py-1 text-[11px] bg-sentinel-secondary border border-sentinel-border rounded text-sentinel-text placeholder:text-sentinel-muted focus:outline-none focus:border-sentinel-copper font-mono-tech"
                autoFocus
              />
            </div>
          </div>

          {/* Sessions List */}
          <div className="max-h-72 overflow-y-auto divide-y divide-sentinel-border/30">
            {sessions.length === 0 ? (
              <div className="p-5 text-center text-xs text-sentinel-muted space-y-2">
                <p>No IPsec sessions recorded yet.</p>
                <Link
                  href="/testbed"
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={() => setIsOpen(false)}
                  className="inline-flex items-center gap-1.5 px-3 py-1 rounded bg-sentinel-copper text-sentinel-bg font-bold text-xs hover:bg-sentinel-copperHover transition-colors"
                >
                  <Plus className="w-3.5 h-3.5" /> Launch Testbed
                </Link>
              </div>
            ) : filteredSessions.length === 0 ? (
              <div className="p-4 text-center text-xs text-sentinel-muted">
                No matching sessions found
              </div>
            ) : (
              filteredSessions.map((s, idx) => {
                const isSelected =
                  s.id.toLowerCase() === selectedSessionId?.toLowerCase() ||
                  s.rawId?.toLowerCase() === selectedSessionId?.toLowerCase();
                const isItemActive = s.status === 'ACTIVE' || idx === 0;

                return (
                  <div
                    key={s.id}
                    onClick={() => {
                      setSelectedSessionId(s.id);
                      setIsOpen(false);
                    }}
                    className={`w-full text-left p-2.5 flex items-center justify-between transition-colors cursor-pointer ${
                      isSelected
                        ? 'bg-sentinel-copper/10 text-sentinel-copper'
                        : 'hover:bg-sentinel-secondary/80 text-sentinel-text'
                    }`}
                  >
                    <div className="space-y-1 min-w-0 pr-2 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-xs tracking-wide">{s.id}</span>
                        {s.rawId && (
                          <span className="text-[10px] text-sentinel-muted truncate max-w-[100px]">
                            {s.rawId}
                          </span>
                        )}
                        <span
                          className={`text-[9px] px-1 py-0.2 rounded font-bold ${
                            isItemActive
                              ? 'bg-sentinel-mint/15 text-sentinel-mint border border-sentinel-mint/30'
                              : 'bg-sentinel-secondary text-sentinel-muted border border-sentinel-border'
                          }`}
                        >
                          {isItemActive ? 'ACTIVE' : 'HISTORIC'}
                        </span>
                      </div>

                      <div className="flex items-center gap-2 text-[10px] text-sentinel-muted truncate">
                        <span>{s.mode}</span>
                        <span>•</span>
                        <span>{s.encryption}</span>
                        <span>•</span>
                        <span>{s.dhGroup}</span>
                      </div>

                      <div className="flex items-center gap-1.5 text-[9px] text-sentinel-muted/70">
                        <Clock className="w-2.5 h-2.5" />
                        <span>{s.establishedAt || 'Recent capture'}</span>
                      </div>
                    </div>

                    <div className="flex-shrink-0 flex items-center gap-1.5">
                      {isSelected && (
                        <div className="w-5 h-5 rounded-full bg-sentinel-copper/20 flex items-center justify-center text-sentinel-copper">
                          <Check className="w-3.5 h-3.5" />
                        </div>
                      )}
                      <button
                        type="button"
                        title="Delete session"
                        onClick={(e) => {
                          e.stopPropagation();
                          if (confirm(`Delete session ${s.id}?`)) {
                            deleteSession(s.id);
                          }
                        }}
                        className="p-1 rounded text-sentinel-muted hover:text-sentinel-critical hover:bg-sentinel-critical/15 transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Footer Action */}
          <div className="p-2 bg-sentinel-secondary/60 flex items-center justify-between text-[10px] text-sentinel-muted border-t border-sentinel-border/40">
            {sessions.length > 0 ? (
              <button
                type="button"
                onClick={() => {
                  if (confirm(`Are you sure you want to delete all ${sessions.length} sessions?`)) {
                    deleteAllSessions();
                    setIsOpen(false);
                  }
                }}
                className="text-sentinel-critical hover:text-red-400 hover:underline flex items-center gap-1 font-semibold"
              >
                <Trash2 className="w-3 h-3" />
                Delete All ({sessions.length})
              </button>
            ) : (
              <span className="text-[10px] text-sentinel-muted italic">No sessions</span>
            )}
            <Link
              href="/sessions"
              onClick={() => setIsOpen(false)}
              className="text-sentinel-copper hover:underline font-semibold ml-auto"
            >
              Session Explorer →
            </Link>
          </div>
        </div>
      )}
    </div>
  );
};
