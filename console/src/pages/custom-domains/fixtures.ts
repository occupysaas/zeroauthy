import type { CustomDomain } from '../../api/client'

// domain builds a wire-shaped custom domain for tests.
export function domain(extra: Partial<CustomDomain> = {}): CustomDomain {
  return {
    custom_domain_id: 'cd_1',
    domain: 'id.acme.test',
    primary: false,
    status: 'pending_verification',
    type: 'auth0_managed_certs',
    origin_domain_name: 'cd-01ab.origin.example.test',
    verification: { methods: [{ name: 'txt', record: 'zeroauthy-domain-verification=abc', domain: '_zeroauthy-domain-verification.id.acme.test' }], status: 'pending' },
    is_default: false,
    custom_client_ip_header: 'x-forwarded-for',
    tls_policy: 'recommended',
    domain_metadata: {},
    relying_party_identifier: 'id.acme.test',
    ...extra,
  }
}
