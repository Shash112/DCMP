/**
 * DCMP Standard HTTP Header Constants
 * Aligned with DCMP_API_Contracts_and_Specifications_v1.0.docx Section 4
 */

export const HTTP_HEADERS = {
  REQUEST_ID: 'x-request-id',
  TENANT_SLUG: 'x-tenant-slug',
  ORGANIZATION_ID: 'x-organization-id',
  DEVICE_ID: 'x-device-id',
  DEVICE_FINGERPRINT: 'x-device-fingerprint',
  CLIENT_VERSION: 'x-client-version',
  IDEMPOTENCY_KEY: 'idempotency-key',
  AUTHORIZATION: 'authorization',
} as const;
