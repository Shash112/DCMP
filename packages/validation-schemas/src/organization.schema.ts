import { z } from 'zod';

export const OrganizationBrandingSchema = z.object({
  primaryColor: z
    .string()
    .regex(/^#[0-9A-Fa-f]{6}$/, 'Must be a valid hex color code')
    .optional(),
  secondaryColor: z
    .string()
    .regex(/^#[0-9A-Fa-f]{6}$/, 'Must be a valid hex color code')
    .optional(),
  accentColor: z
    .string()
    .regex(/^#[0-9A-Fa-f]{6}$/, 'Must be a valid hex color code')
    .optional(),
  logoUrl: z.string().url('Must be a valid URL').optional(),
  faviconUrl: z.string().url('Must be a valid URL').optional(),
  supportEmail: z.string().email('Must be a valid email').optional(),
});

export type OrganizationBrandingInput = z.infer<typeof OrganizationBrandingSchema>;

export const CreateOrganizationSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters').max(100),
  slug: z
    .string()
    .min(2)
    .max(50)
    .regex(/^[a-z0-9-]+$/, 'Slug must contain only lowercase alphanumeric characters and hyphens'),
  adminEmail: z.string().email(),
  adminFirstName: z.string().min(1),
  adminLastName: z.string().min(1),
  branding: OrganizationBrandingSchema.optional(),
});

export type CreateOrganizationInput = z.infer<typeof CreateOrganizationSchema>;
