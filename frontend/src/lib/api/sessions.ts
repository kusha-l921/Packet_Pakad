import { Session } from '@/types';
import { fetchApi } from './client';

export async function fetchSessions(): Promise<Session[]> {
  return fetchApi('/sessions', []);
}

export async function fetchSessionById(id: string): Promise<Session | null> {
  return fetchApi(`/sessions/${id}`, null);
}

export async function fetchActiveTunnelSession(): Promise<Session | null> {
  return fetchApi('/sessions/current', null);
}

export async function deleteSession(id: string): Promise<{ success: boolean; message: string }> {
  try {
    const res = await fetch(`http://localhost:8000/api/v1/sessions/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
    if (!res.ok) throw new Error('Delete failed');
    return await res.json();
  } catch (err: any) {
    return { success: false, message: err?.message || 'Failed to delete session' };
  }
}

export async function deleteAllSessions(): Promise<{ success: boolean; message: string; count: number }> {
  try {
    const res = await fetch('http://localhost:8000/api/v1/sessions', {
      method: 'DELETE',
    });
    if (!res.ok) throw new Error('Delete all failed');
    return await res.json();
  } catch (err: any) {
    return { success: false, message: err?.message || 'Failed to delete all sessions', count: 0 };
  }
}

