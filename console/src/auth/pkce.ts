// PKCE (RFC 7636) and random values for the console's sign-in.

export function base64url(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// randomString returns n random bytes, base64url-encoded (43 characters
// for the default 32 bytes, the verifier length RFC 7636 recommends).
export function randomString(n = 32): string {
  const bytes = new Uint8Array(n)
  crypto.getRandomValues(bytes)
  return base64url(bytes)
}

// challengeFor is the S256 code challenge of verifier.
export async function challengeFor(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return base64url(new Uint8Array(digest))
}

// claims decodes a JWT's payload without verifying it. The console reads
// only display claims from an ID token it received over TLS from the
// token endpoint.
export function claims(jwt: string): Record<string, unknown> {
  const part = jwt.split('.')[1] ?? ''
  const b64 = part.replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4))
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0))
  return JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>
}
