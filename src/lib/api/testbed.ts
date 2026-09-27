import { TestbedConfiguration } from '@/types';
import { defaultTestbedConfig, testbedPresets, testbedDeploymentStages } from '@/data/testbed';
import { simulateNetworkDelay } from './client';

export async function fetchTestbedPresets() {
  return simulateNetworkDelay(testbedPresets, 200);
}

export async function deployTestbed(config: TestbedConfiguration): Promise<{ success: boolean; sessionIdentifier: string }> {
  // Simulates asynchronous deployment
  return simulateNetworkDelay(
    {
      success: true,
      sessionIdentifier: `IPSEC-${Math.floor(10000 + Math.random() * 90000)}`,
    },
    800
  );
}

export { testbedDeploymentStages, defaultTestbedConfig };
