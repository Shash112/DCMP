/**
 * DCMP Inspection & Evidence Domain Models
 * Aligned with DCMP_Complete_Database_Design_v1.0.docx Section 8
 */

export type InspectionStatus =
  'draft' | 'in_progress' | 'submitted' | 'under_review' | 'approved' | 'rejected' | 'cancelled';

export interface InspectionResponse {
  id: string;
  inspectionId: string;
  questionId: string;
  valueText?: string;
  valueNumeric?: number;
  valueBoolean?: boolean;
  valueJson?: Record<string, unknown>;
  isFailed: boolean;
  notes?: string;
  answeredAt?: string;
}

export type EvidenceType = 'photo' | 'signature' | 'document' | 'video';

export interface InspectionEvidence {
  id: string;
  organizationId: string;
  inspectionId: string;
  responseId?: string;
  fileType: EvidenceType;
  s3Key: string;
  fileName: string;
  fileSizeBytes: number;
  mimeType: string;
  checksumSha256?: string;
  gpsLatitude?: number;
  gpsLongitude?: number;
  capturedAt: string;
}

export interface InspectionInstance {
  id: string;
  organizationId: string;
  checklistVersionId: string;
  assignmentId?: string;
  inspectorUserId: string;
  status: InspectionStatus;
  startedAt?: string;
  completedAt?: string;
  submittedAt?: string;
  summaryScore?: number;
  isPassed?: boolean;
  offlineSyncId?: string;
  createdAt: string;
  updatedAt: string;
}
