import { z } from 'zod';

export const QuestionTypeEnum = z.enum([
  'text',
  'number',
  'yes_no',
  'single_choice',
  'multi_choice',
  'photo',
  'signature',
  'date',
  'time',
  'gps',
]);

export const CreateQuestionOptionSchema = z.object({
  label: z.string().min(1),
  value: z.string().min(1),
  isFail: z.boolean().default(false),
  score: z.number().optional(),
});

export const CreateQuestionSchema = z.object({
  title: z.string().min(2, 'Question title is required'),
  description: z.string().optional(),
  type: QuestionTypeEnum,
  isRequired: z.boolean().default(false),
  requireEvidenceOnFail: z.boolean().default(false),
  displayOrder: z.number().int().min(0),
  options: z.array(CreateQuestionOptionSchema).optional(),
});

export const CreateSectionSchema = z.object({
  title: z.string().min(2, 'Section title is required'),
  description: z.string().optional(),
  displayOrder: z.number().int().min(0),
  questions: z.array(CreateQuestionSchema).default([]),
});

export const CreateChecklistTemplateSchema = z.object({
  title: z.string().min(2, 'Title must be at least 2 characters').max(200),
  description: z.string().max(1000).optional(),
  categoryId: z.string().uuid().optional(),
  sections: z.array(CreateSectionSchema).min(1, 'At least one section is required'),
});

export type CreateChecklistTemplateInput = z.infer<typeof CreateChecklistTemplateSchema>;
