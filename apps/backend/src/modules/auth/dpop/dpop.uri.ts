/**
 * Canonical HTTP target URI (htu) construction for RFC 9449 DPoP.
 * Phase 2.1.12 Correction F: preserve path trailing slashes; strip query/fragment;
 * do not trust client-controlled forwarding headers for authorization binding.
 */

export interface HtuBuildInput {
  method: string;
  /** Absolute or path-only URI from the Nest/Express request */
  originalUrl: string;
  protocol: string;
  hostHeader: string;
  /**
   * Public origin configured by the deployment (e.g. https://api.dcmp.com).
   * When set, scheme/host/port come from this value — not from X-Forwarded-*.
   */
  publicOrigin?: string;
  /** Explicitly ignored for security: X-Forwarded-Host / Proto must not override publicOrigin. */
  forwardedHost?: string;
  forwardedProto?: string;
}

export function normalizeHtuFromAbsolute(absoluteUri: string): string {
  let url: URL;
  try {
    url = new URL(absoluteUri);
  } catch {
    throw new Error('Invalid absolute URI for htu');
  }
  if (url.search || url.hash) {
    throw new Error('htu must not include query or fragment');
  }
  const scheme = url.protocol.replace(/:$/, '').toLowerCase();
  const host = url.hostname.toLowerCase();
  const port = url.port;
  const defaultPort =
    (scheme === 'https' && port === '443') || (scheme === 'http' && port === '80');
  const authority = port && !defaultPort ? `${host}:${port}` : host;
  let path = url.pathname || '/';
  // Preserve trailing slash exactly as present (except empty → /)
  if (path === '') path = '/';
  return `${scheme}://${authority}${path}`;
}

/**
 * Build the expected htu for the incoming request.
 * Forwarded headers are recorded but never used when publicOrigin is configured.
 */
export function buildExpectedHtu(input: HtuBuildInput): {
  htu: string;
  ignoredForwardedHeaders: boolean;
} {
  const ignoredForwardedHeaders = Boolean(input.forwardedHost || input.forwardedProto);
  if (input.publicOrigin) {
    const base = new URL(input.publicOrigin);
    const pathOnly = input.originalUrl.split('?')[0].split('#')[0] || '/';
    const combined = new URL(pathOnly, `${base.protocol}//${base.host}`);
    return { htu: normalizeHtuFromAbsolute(combined.toString()), ignoredForwardedHeaders };
  }

  // Local / test fallback: use request protocol + Host (still ignore X-Forwarded-*)
  const scheme = (input.protocol || 'http').replace(/:$/, '').toLowerCase();
  const host = (input.hostHeader || 'localhost').split(',')[0].trim();
  const pathOnly = input.originalUrl.split('?')[0].split('#')[0] || '/';
  return {
    htu: normalizeHtuFromAbsolute(`${scheme}://${host}${pathOnly}`),
    ignoredForwardedHeaders,
  };
}

export function methodsEqual(a: string, b: string): boolean {
  return a.toUpperCase() === b.toUpperCase();
}
