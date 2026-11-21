/**
 * DCMP Standard API Response Contracts
 * Aligned with DCMP_API_Contracts_and_Specifications_v1.0.docx Section 5
 */

export interface ApiMeta {
  requestId: string;
  timestamp?: string;
  page?: number;
  pageSize?: number;
  total?: number;
}

export interface ApiSuccessResponse<T> {
  success: true;
  data: T;
  meta: ApiMeta;
}

export interface ApiErrorDetail {
  field?: string;
  issue: string;
}

export interface ApiErrorPayload {
  code: string;
  message: string;
  details?: ApiErrorDetail[];
  requestId?: string;
}

export interface ApiErrorResponse {
  success: false;
  error: ApiErrorPayload;
}

export type ApiResponse<T> = ApiSuccessResponse<T> | ApiErrorResponse;

export interface PaginationQuery {
  page?: number;
  pageSize?: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

export interface CursorPaginationQuery {
  cursor?: string;
  limit?: number;
}
