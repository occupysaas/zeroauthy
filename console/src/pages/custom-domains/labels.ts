import type { CustomDomain } from '../../api/client'

type T = (key: string) => string

// Literal catalog keys for each wire enum, so every key is checked.
export function statusLabel(t: T, s: CustomDomain['status']): string {
  switch (s) {
    case 'ready': return t('customDomain.statusLabel.ready')
    case 'failed': return t('customDomain.statusLabel.failed')
    default: return t('customDomain.statusLabel.pending_verification')
  }
}

export function verificationLabel(t: T, s: string | undefined): string {
  switch (s) {
    case 'verified': return t('customDomain.verificationLabel.verified')
    case 'failed': return t('customDomain.verificationLabel.failed')
    default: return t('customDomain.verificationLabel.pending')
  }
}

export function certificateLabel(t: T, s: string | undefined): string {
  switch (s) {
    case 'provisioned': return t('customDomain.certificateLabel.provisioned')
    case 'provisioning_failed': return t('customDomain.certificateLabel.provisioning_failed')
    case 'renewing_failed': return t('customDomain.certificateLabel.renewing_failed')
    default: return t('customDomain.certificateLabel.provisioning')
  }
}
