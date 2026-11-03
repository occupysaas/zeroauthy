# Phone delivery

Configure a tenant provider through `POST /api/v2/branding/phone/providers`.
Twilio supports text and voice. The `sns` provider is a zeroauthy extension
and supports text only. Custom providers execute a deployed, bound
`custom-phone-provider` Action. Credentials are write-only and sealed with
the tenant and provider name; an older storage plugin without Phone v1 fails
closed. Use the provider and template `try` endpoints before enabling traffic.

| Purpose | `phone_consolidated_experience: true` | `phone_consolidated_experience: false` |
|---|---|---|
| Passwordless SMS | Tenant phone provider and phone branding template | Connection Twilio or SMS gateway settings and connection template |
| MFA text/voice | Tenant phone provider and phone branding template | Guardian Twilio or phone-message-hook and Guardian template |

New tenants default to the consolidated experience; existing tenants with an
absent setting retain legacy routing. Consolidated routing requires an enabled,
working branding provider; it never falls back when the provider is missing or
disabled. Legacy Guardian `auth0` still requires a working branding provider.

A configured route's delivery failure is returned; there is no fallback to
another provider after a failed send. An SNS voice request is rejected.
Guardian's `phone-message-hook` uses the `send-phone-message` Action trigger;
it is separate from the branding `custom-phone-provider` trigger.

For native SNS delivery, create a dedicated AWS principal with `sns:Publish`
permission, enable the desired SMS destination countries, move the AWS SMS
account out of its sandbox as appropriate, and set spending limits. Select an
AWS region, `delivery_methods: [text]`, optional `sender_id` and `sms_type`
(`Transactional` or `Promotional`). Supply `access_key_id` and
`secret_access_key` privately. This extension signs SNS Query requests with
SigV4. Native SNS is preferable when no custom Action is needed.

A seed uses the existing whole environment-reference syntax for secrets:

```yaml
tenants:
- name: acme
  phone_provider:
    name: twilio
    configuration:
      sid: AC00000000000000000000000000000000
      default_from: '+14155550100'
      delivery_methods: [text, voice]
    credentials:
      auth_token: '${PHONE_TOKEN}'
  phone_templates:
  - type: otp_verify
    content:
      syntax: liquid
      from: Example
      body:
        text: 'Your code is {{ code }}'
        voice: 'Your code is {{ code }}'
  guardian:
    phone_selected_provider: {provider: twilio}
    phone_message_types: {message_types: [sms, voice]}
    phone_settings: {otp_length: 6, otp_expiration_time: 300}
```

Provider and template seed identities are created when absent and existing
operator configuration is preserved on restart. Missing or empty environment
variables fail without exposing values. Never put literal credentials into
seed files. SMS connection `twilio_token` and gateway authentication `secret`
use the same environment references. Guardian `phone_providers` maps provider
names to their documented route bodies; write-only fields also require whole
environment references.

The following original examples implement text delivery only. Store endpoint
URLs and credentials as tenant Action secrets; choose vendor URLs and payloads
for your account. Failures throw a fixed error without response bodies or
recipient data. Each code block is built by `TestExampleActionsCompile`.
Use fake endpoints for delivery testing before supplying real credentials.

## Vonage

Set `ENDPOINT` to your SMS API endpoint, `API_KEY`, `API_SECRET`, and `FROM`.
The payload and queued-message status follow the [Vonage SMS API](https://developer.vonage.com/en/api/sms).

```javascript
exports.onExecuteCustomPhoneProvider = async (event, api) => {
  if (event.notification.delivery_method !== 'text') {
    api.notification.drop('unsupported delivery method');
    return;
  }
  const body = new URLSearchParams({
    api_key: event.secrets.API_KEY,
    api_secret: event.secrets.API_SECRET,
    from: event.secrets.FROM,
    to: event.notification.recipient,
    text: event.notification.as_text
  });
  const response = await fetch(event.secrets.ENDPOINT, {method: 'POST', body});
  if (!response.ok) throw new Error('phone delivery failed');
  const result = await response.json();
  if (result.messages?.[0]?.status !== '0') throw new Error('phone delivery failed');
};
```

## Azure Communication Services

Set `ENDPOINT` to your ACS SMS send endpoint including its API version, `FROM`,
and `BEARER_TOKEN` to a valid short-lived Azure access token. Arrange token
rotation outside this example; a static token expires. The payload follows
the [ACS SMS send API](https://learn.microsoft.com/en-us/rest/api/communication/sms/sms/send).

```javascript
exports.onExecuteCustomPhoneProvider = async (event, api) => {
  if (event.notification.delivery_method !== 'text') {
    api.notification.drop('unsupported delivery method');
    return;
  }
  const response = await fetch(event.secrets.ENDPOINT, {
    method: 'POST',
    headers: {'content-type': 'application/json', authorization: `Bearer ${event.secrets.BEARER_TOKEN}`},
    body: JSON.stringify({from: event.secrets.FROM, message: event.notification.as_text,
      smsRecipients: [{to: event.notification.recipient}]})
  });
  if (!response.ok) throw new Error('phone delivery failed');
  const result = await response.json();
  if (!result.value?.[0]?.successful) throw new Error('phone delivery failed');
};
```

## SNS through an Action

Set `REGION`, `ACCESS_KEY_ID`, `SECRET_ACCESS_KEY`, and `ENDPOINT` to the
regional SNS HTTPS endpoint. This original example signs an SNS Query Publish
request using SigV4. Its endpoint has no path or query components. For temporary
AWS credentials, also set `SESSION_TOKEN`. The native provider avoids maintaining
this signing code in an Action. See [SNS Publish](https://docs.aws.amazon.com/sns/latest/api/API_Publish.html).

```javascript
exports.onExecuteCustomPhoneProvider = async (event, api) => {
  if (event.notification.delivery_method !== 'text') {
    api.notification.drop('unsupported delivery method');
    return;
  }
  const crypto = require('crypto');
  const hash = value => crypto.createHash('sha256').update(value).digest('hex');
  const hmac = (key, value) => crypto.createHmac('sha256', key).update(value).digest();
  const url = new URL(event.secrets.ENDPOINT);
  const timestamp = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
  const date = timestamp.slice(0, 8);
  const scope = `${date}/${event.secrets.REGION}/sns/aws4_request`;
  const body = new URLSearchParams({Action: 'Publish', Version: '2010-03-31',
    PhoneNumber: event.notification.recipient, Message: event.notification.as_text}).toString();
  const headers = {'content-type': 'application/x-www-form-urlencoded',
    host: url.host, 'x-amz-date': timestamp};
  if (event.secrets.SESSION_TOKEN) headers['x-amz-security-token'] = event.secrets.SESSION_TOKEN;
  const names = Object.keys(headers).sort();
  const canonicalHeaders = names.map(name => `${name}:${headers[name].trim()}\n`).join('');
  const signed = names.join(';');
  const canonical = ['POST', '/', '', canonicalHeaders, signed, hash(body)].join('\n');
  const toSign = ['AWS4-HMAC-SHA256', timestamp, scope, hash(canonical)].join('\n');
  const signingKey = hmac(hmac(hmac(hmac(`AWS4${event.secrets.SECRET_ACCESS_KEY}`, date),
    event.secrets.REGION), 'sns'), 'aws4_request');
  headers.authorization = `AWS4-HMAC-SHA256 Credential=${event.secrets.ACCESS_KEY_ID}/${scope}, SignedHeaders=${signed}, Signature=${hmac(signingKey, toSign).toString('hex')}`;
  const response = await fetch(url, {method: 'POST', headers, body});
  if (!response.ok) throw new Error('phone delivery failed');
};
```
