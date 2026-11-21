/**
 * DCMP Canonical API Route Contracts
 * Derived from DCMP_API_OpenAPI_v1.0.yaml and DCMP_API_Contracts_and_Specifications_v1.0.docx
 */

export const API_BASE_PATH = '/api/v1';

export const API_ROUTES = {
  HEALTH: `${API_BASE_PATH}/health`,

  AUTH: {
    LOGIN: `${API_BASE_PATH}/auth/login`,
    REFRESH: `${API_BASE_PATH}/auth/refresh`,
    LOGOUT: `${API_BASE_PATH}/auth/logout`,
    ME: `${API_BASE_PATH}/auth/me`,
    FORGOT_PASSWORD: `${API_BASE_PATH}/auth/forgot-password`,
    RESET_PASSWORD: `${API_BASE_PATH}/auth/reset-password`,
  },

  ORGANIZATIONS: {
    CURRENT: `${API_BASE_PATH}/organizations/current`,
    BRANDING: `${API_BASE_PATH}/organizations/branding`,
    SETTINGS: `${API_BASE_PATH}/organizations/settings`,
    LOCATIONS: `${API_BASE_PATH}/locations`,
    DEPARTMENTS: `${API_BASE_PATH}/departments`,
  },

  USERS: {
    LIST: `${API_BASE_PATH}/users`,
    DETAIL: (userId: string) => `${API_BASE_PATH}/users/${userId}`,
    ROLES: `${API_BASE_PATH}/roles`,
  },

  CHECKLISTS: {
    LIST: `${API_BASE_PATH}/checklists`,
    DETAIL: (checklistId: string) => `${API_BASE_PATH}/checklists/${checklistId}`,
    VERSIONS: (checklistId: string) => `${API_BASE_PATH}/checklists/${checklistId}/versions`,
    PUBLISH: (checklistId: string, versionId: string) =>
      `${API_BASE_PATH}/checklists/${checklistId}/versions/${versionId}/publish`,
  },

  ASSIGNMENTS: {
    LIST: `${API_BASE_PATH}/assignments`,
    DETAIL: (assignmentId: string) => `${API_BASE_PATH}/assignments/${assignmentId}`,
    MY_ASSIGNMENTS: `${API_BASE_PATH}/assignments/my`,
  },

  INSPECTIONS: {
    LIST: `${API_BASE_PATH}/inspections`,
    DETAIL: (inspectionId: string) => `${API_BASE_PATH}/inspections/${inspectionId}`,
    SUBMIT: (inspectionId: string) => `${API_BASE_PATH}/inspections/${inspectionId}/submit`,
    RESPONSES: (inspectionId: string) => `${API_BASE_PATH}/inspections/${inspectionId}/responses`,
    EVIDENCE: (inspectionId: string) => `${API_BASE_PATH}/inspections/${inspectionId}/evidence`,
    APPROVE: (inspectionId: string) => `${API_BASE_PATH}/inspections/${inspectionId}/approve`,
    REJECT: (inspectionId: string) => `${API_BASE_PATH}/inspections/${inspectionId}/reject`,
  },

  SYNC: {
    PULL: `${API_BASE_PATH}/sync/pull`,
    PUSH: `${API_BASE_PATH}/sync/push`,
    STATUS: `${API_BASE_PATH}/sync/status`,
  },

  LICENSING: {
    ACTIVATE: `${API_BASE_PATH}/licenses/activate`,
    STATUS: `${API_BASE_PATH}/licenses/status`,
  },

  PLATFORM_ADMIN: {
    TENANTS: `${API_BASE_PATH}/admin/tenants`,
    TENANT_DETAIL: (tenantId: string) => `${API_BASE_PATH}/admin/tenants/${tenantId}`,
    LICENSES: `${API_BASE_PATH}/admin/licenses`,
    SUPPORT_TICKETS: `${API_BASE_PATH}/admin/support/tickets`,
    SUPPORT_ACCESS: `${API_BASE_PATH}/admin/support/access`,
  },
} as const;
