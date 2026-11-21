import { ApiResponse } from '@dcmp/shared-types';
import { HTTP_HEADERS } from '@dcmp/api-contracts';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000/api/v1';

export class ApiClient {
  private static tenantSlug: string = 'default';

  static setTenantSlug(slug: string) {
    this.tenantSlug = slug;
  }

  static async get<T>(path: string): Promise<ApiResponse<T>> {
    const res = await fetch(`${API_BASE_URL}${path}`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        [HTTP_HEADERS.TENANT_SLUG]: this.tenantSlug,
      },
      cache: 'no-store',
    });

    return res.json();
  }

  static async post<T, B = unknown>(path: string, body: B): Promise<ApiResponse<T>> {
    const res = await fetch(`${API_BASE_URL}${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        [HTTP_HEADERS.TENANT_SLUG]: this.tenantSlug,
      },
      body: JSON.stringify(body),
    });

    return res.json();
  }
}
