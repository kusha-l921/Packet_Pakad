import { Session } from '@/types';
import { mockSessions } from '@/data/sessions';
import { simulateNetworkDelay } from './client';

export async function fetchSessions(): Promise<Session[]> {
  return simulateNetworkDelay(mockSessions, 350);
}

export async function fetchSessionById(id: string): Promise<Session | null> {
  const found = mockSessions.find((s) => s.id.toLowerCase() === id.toLowerCase());
  return simulateNetworkDelay(found || null, 300);
}

export async function fetchActiveTunnelSession(): Promise<Session> {
  return simulateNetworkDelay(mockSessions[0], 250);
}
