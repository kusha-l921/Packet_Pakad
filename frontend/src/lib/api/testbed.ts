import { TestbedConfiguration } from '@/types';
import { defaultTestbedConfig, testbedPresets, testbedDeploymentStages } from '@/data/testbed';
import { API_BASE_URL, fetchApi } from './client';

export async function fetchTestbedPresets() {
  return testbedPresets;
}

export interface TestbedStatus {
  docker_connected: boolean;
  docker_message: string;
  containers: Record<string, any>;
  sas: { established: boolean; raw?: string; ike?: any; child?: any };
  sniffer_running: boolean;
  is_deploying: boolean;
  current_stage?: number;
  last_session_id?: string;
  has_active_tunnel?: boolean;
}

export async function fetchTestbedStatus(): Promise<TestbedStatus> {
  return fetchApi<TestbedStatus>('/testbed/status', {
    docker_connected: false,
    docker_message: '',
    containers: {},
    sas: { established: false },
    sniffer_running: false,
    is_deploying: false,
    current_stage: 0,
    last_session_id: 'IPSEC-00421',
    has_active_tunnel: false,
  });
}

export async function fetchTestbedLogs(): Promise<string[]> {
  const res = await fetchApi<{ logs: string[] }>('/testbed/logs', { logs: [] });
  return res.logs || [];
}

export async function deployTestbed(
  config: TestbedConfiguration
): Promise<{ success: boolean; is_deploying?: boolean; sessionIdentifier: string; message?: string; error?: string }> {
  try {
    const res = await fetch(`${API_BASE_URL}/testbed/deploy`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(config),
    });
    if (res.ok) {
      return await res.json();
    }
  } catch (e) {
    console.error('Failed to trigger deployment API', e);
  }
  return {
    success: false,
    sessionIdentifier: `IPSEC-${Math.floor(10000 + Math.random() * 90000)}`,
  };
}

export async function triggerTestbedTraffic(
  trafficType: string = 'Video'
): Promise<{ success: boolean; message: string }> {
  try {
    const res = await fetch(`${API_BASE_URL}/testbed/traffic`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ trafficType }),
    });
    if (res.ok) {
      return await res.json();
    }
  } catch (e) {
    console.error('Failed to trigger traffic API', e);
  }
  return { success: false, message: 'Failed to contact traffic API' };
}

export { testbedDeploymentStages, defaultTestbedConfig };
