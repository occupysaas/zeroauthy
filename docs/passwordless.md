# Passwordless sign-in

Create `email` or `sms` strategy connections, then enable the desired clients.
`POST /passwordless/start` accepts a client, connection and `email` or
`phone_number`. Email accepts `send: code` or `send: link`; SMS uses a code.
Redeem a code through `/oauth/token` using
`http://auth0.com/oauth/grant-type/passwordless/otp`, the connection as
`realm`, the identifier as `username`, and `otp`. A client must explicitly
allow the grant. Public clients require no secret; confidential clients use
the configured token endpoint authentication method.

Email links use `/passwordless/verify_redirect`. Links expire, are consumed
once, and are not interchangeable with codes. Codes are hashed in storage,
expire, have bounded verification attempts, and are replaced on resend.
Generic start responses avoid disclosing whether an account already exists.
Successful verification creates the passwordless identity when signup is
allowed and enters normal post-login Actions, consent and MFA processing.
Email and SMS identities do not automatically link to existing database users.

The hosted login page offers passwordless connections and code/link screens.
Magic-link browser restrictions and the exact limits follow D-0060 and the
frozen phone contract. Delivery needs a working tenant email provider or
[phone route](phone-providers.md); successful configuration storage alone
does not demonstrate external delivery.

Seed examples:

```yaml
tenants:
- name: acme
  connections:
  - name: email
    strategy: email
    options: {otp_length: 6, totp: {time_step: 180}}
  - name: sms
    strategy: sms
    options:
      provider: twilio
      twilio_sid: AC00000000000000000000000000000000
      twilio_token: '${PHONE_TOKEN}'
      from: '+14155550100'
```

Database phone identifiers are separate from passwordless SMS identities.
Enable `options.attributes.phone_number.identifier.active` only after fixing
invalid or duplicate existing phone numbers. Both Management API and seed
writers apply the same read-only pre-check before enabling. Signup verifies
phone ownership with a short-lived code; password login still checks the
password and enforces MFA. Phone numbers normalize to E.164 and lookup is
scoped to the tenant and database connection. Changing a number does not
carry verification from the old number.

Passwordless starts and deliveries enforce identifier/IP budgets and tenant
[attack protection](attack-protection.md). Never log codes, links, token
responses or unmasked recipients during integration debugging.
