/**
 * DCMP Canonical Color Design Tokens
 * Aligned with DCMP_UI_UX_Design_Specification_v1.0.docx Section 3.1
 */

export const colors = {
  primary: {
    50: '#EEF2FF',
    100: '#E0E7FF',
    200: '#C7D2FE',
    300: '#A5B4FC',
    400: '#818CF8',
    500: '#6366F1',
    600: '#4656C8', // Primary brand accent
    700: '#3730A3',
    800: '#312E81',
    900: '#1E1B4B',
  },
  neutral: {
    50: '#F8FAFC',
    100: '#F1F5F9',
    200: '#E2E8F0',
    300: '#CBD5E1',
    400: '#94A3B8',
    500: '#64748B',
    600: '#475569',
    700: '#334155',
    800: '#1E293B',
    900: '#0F172A',
  },
  success: {
    50: '#ECFDF5',
    500: '#10B981',
    700: '#047857',
  },
  warning: {
    50: '#FFFBEB',
    500: '#F59E0B',
    700: '#B45309',
  },
  danger: {
    50: '#FEF2F2',
    500: '#EF4444',
    700: '#B91C1C',
  },
  info: {
    50: '#F0F9FF',
    500: '#0EA5E9',
    700: '#0369A1',
  },
  surface: {
    background: '#F8FAFC',
    card: '#FFFFFF',
    border: '#E2E8F0',
    sidebar: '#0F172A',
  },
} as const;
