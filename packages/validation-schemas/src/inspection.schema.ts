import { z } from 'zod';

export const SaveInspectionResponseSchema = z.object({
  questionId: z.string().uuid(),
  valueText: z.string().optional(),
  valueNumeric: z.number().optional(),
  valueBoolean: z.boolean().optional(),
  valueJson: z.record(z.unknown()).optional(),
  isFailed: z.boolean().default(false),
  notes: z.string().max(1000).optional(),
});

export const SubmitInspectionSchema = z.object({
  responses: z.array(SaveInspectionResponseSchema).min(1, 'At least one response is required'),
  summaryNotes: z.string().max(2000).optional(),
  offlineSyncId: z.string().uuid().optional(),
});

export type SubmitInspectionInput = z.infer<typeof SubmitInspectionSchema>;
