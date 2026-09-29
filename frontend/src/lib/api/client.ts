/**
 * IPsec Sentinel API Client
 * 
 * Provides an asynchronous abstraction layer designed to interface directly
 * with the forthcoming FastAPI backend (/api/v1/...).
 * Currently backed by typed, deterministic mock engines with realistic network latency.
 */

export const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';

export async function fetchApi<T>(path: string, fallback: T, options?: RequestInit): Promise<T> {
  try {
    const url = `${API_BASE_URL}${path.startsWith('/') ? path : '/' + path}`;
    const res = await fetch(url, {
      ...options,
      headers: {
        'Accept': 'application/json',
        ...(options?.headers || {}),
      },
    });
    if (res.ok) {
      return (await res.json()) as T;
    }
  } catch (err) {
    // Backend unreachable or offline, fallback safely
  }
  return fallback;
}

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
