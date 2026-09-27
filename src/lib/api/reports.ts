import { Report } from '@/types';
import { mockExecutiveReport, mockTechnicalReport } from '@/data/reports';
import { simulateNetworkDelay } from './client';

export async function fetchReports(): Promise<{ executive: Report; technical: Report }> {
  return simulateNetworkDelay(
    {
      executive: mockExecutiveReport,
      technical: mockTechnicalReport,
    },
    300
  );
}

export async function exportReportJson(report: Report): Promise<string> {
  return simulateNetworkDelay(JSON.stringify(report, null, 2), 200);
}
