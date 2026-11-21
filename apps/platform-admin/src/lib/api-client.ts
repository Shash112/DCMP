import { ApiResponse } from '@dcmp/shared-types';

const ADMIN_API_BASE_URL = process.env.NEXT_PUBLIC_ADMIN_API_URL || 'http://localhost:4000/api/v1';

export class AdminApiClient {
  private static adminToken: string | null = null;

  static setAdminToken(token: string | null) {
    this.adminToken = token;
  }

  static async get<T>(path: string): Promise<ApiResponse<T>> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (this.adminToken) {
      headers['Authorization'] = `Bearer ${this.adminToken}`;
    }

    const res = await fetch(`${ADMIN_API_BASE_URL}${path}`, {
      method: 'GET',
      headers,
      cache: 'no-store',
    });

    return res.json();
  }

  static async post<T, B = unknown>(path: string, body: B): Promise<ApiResponse<T>> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (this.adminToken) {
      headers['Authorization'] = `Bearer ${this.adminToken}`;
    }

    const res = await fetch(`${ADMIN_API_BASE_URL}${path}`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });

    return res.json();
  }
}
