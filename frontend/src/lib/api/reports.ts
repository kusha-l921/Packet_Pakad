import { Report } from '@/types';
import { fetchApi } from './client';

export interface RagReportData {
  exists: boolean;
  markdown: string;
  title: string;
  session_spi: string;
  has_html: boolean;
}

export async function fetchReports(sessionId?: string): Promise<{ executive: Report | null; technical: Report | null }> {
  const query = sessionId ? `?session_id=${encodeURIComponent(sessionId)}` : '';
  const exec = await fetchApi<Report | null>(`/reports/executive${query}`, null);
  const tech = await fetchApi<Report | null>(`/reports/technical${query}`, null);
  return {
    executive: exec,
    technical: tech,
  };
}

export async function fetchRagReport(sessionId?: string): Promise<RagReportData> {
  const query = sessionId ? `?session_id=${encodeURIComponent(sessionId)}` : '';
  return await fetchApi<RagReportData>(`/reports/rag${query}`, {
    exists: false,
    markdown: '',
    title: 'Quantum-Safe IPsec & IKEv2 Compliance Audit Report',
    session_spi: '0x9988776655443322',
    has_html: false,
  });
}

export async function exportReportJson(report: Report): Promise<string> {
  return JSON.stringify(report, null, 2);
}
