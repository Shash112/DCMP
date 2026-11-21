/**
 * DCMP Roles and Permissions Taxonomy
 * Aligned with DCMP_User_Roles_and_Permissions_Matrix_v1.0.docx
 */

export enum PlatformRole {
  SUPER_ADMIN = 'PLATFORM_SUPER_ADMIN',
  OPERATIONS_ADMIN = 'PLATFORM_OPERATIONS_ADMIN',
  SUPPORT_AGENT = 'PLATFORM_SUPPORT_AGENT',
}

export enum CustomerRole {
  OWNER = 'CUSTOMER_OWNER',
  ADMIN = 'CUSTOMER_ADMIN',
  MANAGER = 'MANAGER',
  SUPERVISOR = 'SUPERVISOR',
  INSPECTOR = 'INSPECTOR',
  AUDITOR = 'AUDITOR',
}

export enum PermissionKey {
  // Platform Permissions
  PLATFORM_MANAGE_TENANTS = 'platform:tenants:manage',
  PLATFORM_MANAGE_LICENSES = 'platform:licenses:manage',
  PLATFORM_VIEW_METRICS = 'platform:metrics:view',
  PLATFORM_REQUEST_SUPPORT_ACCESS = 'platform:support:request_access',

  // Tenant Administration
  ORG_SETTINGS_UPDATE = 'org:settings:update',
  ORG_USERS_MANAGE = 'org:users:manage',
  ORG_ROLES_MANAGE = 'org:roles:manage',
  ORG_LOCATIONS_MANAGE = 'org:locations:manage',

  // Checklist Management
  CHECKLIST_CREATE = 'checklist:create',
  CHECKLIST_EDIT = 'checklist:edit',
  CHECKLIST_PUBLISH = 'checklist:publish',
  CHECKLIST_ARCHIVE = 'checklist:archive',

  // Assignments & Scheduling
  ASSIGNMENT_CREATE = 'assignment:create',
  ASSIGNMENT_MANAGE = 'assignment:manage',
  ASSIGNMENT_VIEW = 'assignment:view',

  // Inspections
  INSPECTION_EXECUTE = 'inspection:execute',
  INSPECTION_SUBMIT = 'inspection:submit',
  INSPECTION_APPROVE = 'inspection:approve',
  INSPECTION_REJECT = 'inspection:reject',
  INSPECTION_VIEW = 'inspection:view',

  // Evidence
  EVIDENCE_UPLOAD = 'evidence:upload',
  EVIDENCE_VIEW = 'evidence:view',

  // Issues & Actions
  ISSUE_CREATE = 'issue:create',
  ISSUE_ASSIGN = 'issue:assign',
  ISSUE_RESOLVE = 'issue:resolve',

  // Reports & Analytics
  REPORT_VIEW = 'report:view',
  REPORT_EXPORT = 'report:export',
}

export interface ResourceScope {
  tenantId: string;
  locationIds?: string[];
  departmentIds?: string[];
  teamIds?: string[];
}
