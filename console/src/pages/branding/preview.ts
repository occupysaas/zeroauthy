// srcdoc inherits the console's CSP. Rebind the validated preview's style
// nonce to the per-document nonce; scripts stay disabled in both policies.
export function bindPreviewStyleNonce(source: string): string {
  const nonce = document.querySelector('meta[name="zeroauthy-preview-style-nonce"]')?.getAttribute('content')
  const prior = source.match(/<style\s+nonce="([A-Za-z0-9_-]{22})"/i)?.[1]
  return nonce && /^[A-Za-z0-9_-]{22}$/.test(nonce) && prior ? source.replaceAll(prior, nonce) : source
}
