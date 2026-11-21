/**
 * DCMP Checklist Domain Models
 * Aligned with DCMP_Complete_Database_Design_v1.0.docx Section 6
 */

export type QuestionType =
  | 'text'
  | 'number'
  | 'yes_no'
  | 'single_choice'
  | 'multi_choice'
  | 'photo'
  | 'signature'
  | 'date'
  | 'time'
  | 'gps';

export interface QuestionOption {
  id: string;
  label: string;
  value: string;
  isFail?: boolean;
  score?: number;
}

export interface QuestionCondition {
  id: string;
  targetQuestionId: string;
  operator: 'equals' | 'not_equals' | 'contains' | 'greater_than' | 'less_than';
  value: string;
  action: 'show' | 'hide' | 'require';
}

export interface ChecklistQuestion {
  id: string;
  sectionId: string;
  title: string;
  description?: string;
  type: QuestionType;
  isRequired: boolean;
  requireEvidenceOnFail: boolean;
  displayOrder: number;
  options?: QuestionOption[];
  conditions?: QuestionCondition[];
}

export interface ChecklistSection {
  id: string;
  versionId: string;
  title: string;
  description?: string;
  displayOrder: number;
  questions: ChecklistQuestion[];
}

export interface ChecklistVersion {
  id: string;
  templateId: string;
  versionNumber: number;
  isPublished: boolean;
  publishedAt?: string;
  sections: ChecklistSection[];
  snapshotJson?: Record<string, unknown>;
}

export interface ChecklistTemplate {
  id: string;
  organizationId: string;
  title: string;
  description?: string;
  categoryId?: string;
  isActive: boolean;
  currentVersionNumber: number;
  createdAt: string;
  updatedAt: string;
}
