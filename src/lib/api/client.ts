/**
 * IPsec Sentinel API Client
 * 
 * Provides an asynchronous abstraction layer designed to interface directly
 * with the forthcoming FastAPI backend (/api/v1/...).
 * Currently backed by typed, deterministic mock engines with realistic network latency.
 */

export const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';

export async function simulateNetworkDelay<T>(data: T, delayMs: number = 400): Promise<T> {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve(data);
    }, delayMs);
  });
}

export class ApiError extends Error {
  constructor(public statusCode: number, message: string, public details?: any) {
    super(message);
    this.name = 'ApiError';
  }
}
