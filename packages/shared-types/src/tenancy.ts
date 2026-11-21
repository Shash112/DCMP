/**
 * DCMP Multi-Tenant & Organization Models
 * Aligned with DCMP_Complete_Database_Design_v1.0.docx Section 4
 */

export interface TenantContext {
  organizationId: string;
  tenantSlug: string;
  subdomain?: string;
}

export type OrganizationStatus = 'active' | 'suspended' | 'trial' | 'archived';

export interface OrganizationBranding {
  primaryColor?: string;
  secondaryColor?: string;
  accentColor?: string;
  logoUrl?: string;
  faviconUrl?: string;
  supportEmail?: string;
  customCss?: string;
}

export interface OrganizationSettings {
  timezone: string;
  dateFormat: string;
  requireGps: boolean;
  retentionDays: number;
  autoCloseIssues: boolean;
  branding?: OrganizationBranding;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  status: OrganizationStatus;
  settings?: OrganizationSettings;
  createdAt: string;
  updatedAt: string;
}

export interface Location {
  id: string;
  organizationId: string;
  name: string;
  code?: string;
  address?: string;
  timezone?: string;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface Department {
  id: string;
  organizationId: string;
  locationId?: string;
  name: string;
  code?: string;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}
