import { z } from 'zod';

export const LoginSchema = z.object({
  email: z.string().email('Must be a valid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters long'),
  tenantSlug: z.string().optional(),
});

export type LoginInput = z.infer<typeof LoginSchema>;

export const RefreshTokenSchema = z.object({
  refreshToken: z.string().min(1, 'Refresh token is required'),
});

export type RefreshTokenInput = z.infer<typeof RefreshTokenSchema>;

export const ForgotPasswordSchema = z.object({
  email: z.string().email('Must be a valid email address'),
});

export type ForgotPasswordInput = z.infer<typeof ForgotPasswordSchema>;

export const ResetPasswordSchema = z.object({
  token: z.string().min(1, 'Reset token is required'),
  newPassword: z.string().min(8, 'Password must be at least 8 characters long'),
});

export type ResetPasswordInput = z.infer<typeof ResetPasswordSchema>;
