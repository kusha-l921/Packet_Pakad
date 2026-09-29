'use client';

import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import { Session } from '@/types';
import { fetchSessions, deleteSession as apiDeleteSession, deleteAllSessions as apiDeleteAllSessions } from '@/lib/api/sessions';

interface SessionContextType {
  sessions: Session[];
  selectedSessionId: string | null;
  selectedSession: Session | null;
  setSelectedSessionId: (id: string | null) => void;
  deleteSession: (id: string) => Promise<boolean>;
  deleteAllSessions: () => Promise<boolean>;
  refreshSessions: () => Promise<void>;
  isLoading: boolean;
}

const SessionContext = createContext<SessionContextType | undefined>(undefined);

export const SessionProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [selectedSessionId, setSelectedSessionIdState] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const refreshSessions = useCallback(async () => {
    try {
      const data = await fetchSessions();
      if (Array.isArray(data)) {
        setSessions(data);
        if (data.length === 0) {
          setSelectedSessionIdState(null);
          if (typeof window !== 'undefined') {
            localStorage.removeItem('sentinel_selected_session');
          }
        }
      }
    } catch (e) {
      console.error('Failed to fetch sessions in SessionProvider', e);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Initial load and periodic polling
  useEffect(() => {
    refreshSessions();
    const interval = setInterval(refreshSessions, 3500);
    return () => clearInterval(interval);
  }, [refreshSessions]);

  // Sync selected session with URL or localStorage or default to latest
  useEffect(() => {
    if (sessions.length === 0) {
      setSelectedSessionIdState(null);
      return;
    }

    if (!selectedSessionId || !sessions.some(s => s.id.toLowerCase() === selectedSessionId.toLowerCase() || s.rawId?.toLowerCase() === selectedSessionId.toLowerCase())) {
      // 1. Check URL query param
      if (typeof window !== 'undefined') {
        const params = new URLSearchParams(window.location.search);
        const urlSession = params.get('session');
        if (urlSession) {
          const match = sessions.find(
            (s) =>
              s.id.toLowerCase() === urlSession.toLowerCase() ||
              s.rawId?.toLowerCase() === urlSession.toLowerCase()
          );
          if (match) {
            setSelectedSessionIdState(match.id);
            return;
          }
        }

        // 2. Check localStorage
        const stored = localStorage.getItem('sentinel_selected_session');
        if (stored) {
          const match = sessions.find(
            (s) =>
              s.id.toLowerCase() === stored.toLowerCase() ||
              s.rawId?.toLowerCase() === stored.toLowerCase()
          );
          if (match) {
            setSelectedSessionIdState(match.id);
            return;
          }
        }
      }

      // 3. Fallback to newest session (first item)
      setSelectedSessionIdState(sessions[0].id);
    }
  }, [sessions, selectedSessionId]);

  const setSelectedSessionId = (id: string | null) => {
    setSelectedSessionIdState(id);
    if (typeof window !== 'undefined') {
      try {
        if (id) {
          localStorage.setItem('sentinel_selected_session', id);
          const url = new URL(window.location.href);
          url.searchParams.set('session', id);
          window.history.replaceState({}, '', url.toString());
        } else {
          localStorage.removeItem('sentinel_selected_session');
          const url = new URL(window.location.href);
          url.searchParams.delete('session');
          window.history.replaceState({}, '', url.toString());
        }
      } catch {
        // ignore storage/history errors
      }
    }
  };

  const deleteSession = async (id: string): Promise<boolean> => {
    try {
      const res = await apiDeleteSession(id);
      if (res.success) {
        setSessions((prev) => {
          const updated = prev.filter(
            (s) => s.id.toLowerCase() !== id.toLowerCase() && s.rawId?.toLowerCase() !== id.toLowerCase()
          );
          if (selectedSessionId?.toLowerCase() === id.toLowerCase()) {
            setSelectedSessionId(updated[0]?.id || null);
          }
          return updated;
        });
        return true;
      }
      return false;
    } catch {
      return false;
    }
  };

  const deleteAllSessions = async (): Promise<boolean> => {
    try {
      const res = await apiDeleteAllSessions();
      if (res.success) {
        setSessions([]);
        setSelectedSessionId(null);
        return true;
      }
      return false;
    } catch {
      return false;
    }
  };

  const selectedSession =
    sessions.find(
      (s) =>
        s.id.toLowerCase() === selectedSessionId?.toLowerCase() ||
        s.rawId?.toLowerCase() === selectedSessionId?.toLowerCase()
    ) || sessions[0] || null;

  return (
    <SessionContext.Provider
      value={{
        sessions,
        selectedSessionId,
        selectedSession,
        setSelectedSessionId,
        deleteSession,
        deleteAllSessions,
        refreshSessions,
        isLoading,
      }}
    >
      {children}
    </SessionContext.Provider>
  );
};

export const useSession = (): SessionContextType => {
  const context = useContext(SessionContext);
  if (!context) {
    throw new Error('useSession must be used within a SessionProvider');
  }
  return context;
};
