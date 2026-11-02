// Executable member vocabulary from the frozen Plan 33 Actions contract.
export function mfaHints(trigger: string): string {
  if(!['post-login', 'password-reset-post-challenge'].includes(trigger)) return ''
  const factors = `type MFAFactor = { type: "otp" | "email" | "recovery-code" };
type MFAOptions = { additionalFactors?: MFAFactor[] };
api.authentication.challengeWith(factor: MFAFactor, options?: MFAOptions): void;
api.authentication.challengeWithAny(factors: MFAFactor[]): void;`
  const event = `event.user.enrolledFactors: Array<{ type: string; options?: Record<string, unknown> }>;
event.authentication.methods: Array<{ name: "mfa" | string; timestamp: string }>;`
  return trigger === 'post-login' ? `${factors}
api.authentication.enrollWith(factor: MFAFactor, options?: MFAOptions): void;
api.authentication.enrollWithAny(factors: MFAFactor[]): void;
api.multifactor.enable(provider: "any" | "google-authenticator" | "guardian" | "none" | "duo", options?: { allowRememberBrowser?: boolean }): void;
${event}` : factors
}
