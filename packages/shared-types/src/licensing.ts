/**
 * DCMP Licensing & Mobile Device Activation Models
 * Aligned with DCMP_Complete_Database_Design_v1.0.docx Sections 4 & 10
 */

export type LicenseTier = 'starter' | 'professional' | 'enterprise';
export type LicenseStatus = 'active' | 'suspended' | 'expired' | 'trial';

export interface LicensePlan {
  id: string;
  name: string;
  tier: LicenseTier;
  maxUsers: number;
  maxDevices: number;
  maxTemplates: number;
  offlineSyncEnabled: boolean;
  isActive: boolean;
}

export interface CustomerLicense {
  id: string;
  organizationId: string;
  planId: string;
  licenseKey: string;
  status: LicenseStatus;
  maxDevices: number;
  activatedDevicesCount: number;
  expiresAt: string;
}

export interface MobileDevice {
  id: string;
  organizationId: string;
  deviceFingerprint: string;
  deviceName: string;
  osVersion: string;
  appVersion: string;
  isActive: boolean;
  lastSyncAt?: string;
  activatedAt: string;
}

export interface DeviceActivationRequest {
  activationKey: string;
  deviceFingerprint: string;
  deviceName: string;
  osVersion: string;
  appVersion: string;
}

export interface DeviceActivationResponse {
  deviceToken: string;
  organizationSlug: string;
  organizationName: string;
  branding?: Record<string, unknown>;
  entitlements: Record<string, unknown>;
}
