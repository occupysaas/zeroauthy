// Synthetic values only: these templates are editable, never production data.
const user = { user_id: 'auth0|sample', email: 'demo@example.test', email_verified: false, user_metadata: {}, app_metadata: {} }
const client = { client_id: 'sample-client', name: 'Sample application', metadata: {} }
const tenant = { id: 'sample', friendly_name: 'Sample tenant', support_email: '', support_url: '' }
const request = { ip: '192.0.2.1', hostname: 'sample.example.test', method: 'POST', user_agent: 'Console sample', language: 'en', query: {}, body: {} }
const connection = { id: 'con_sample', name: 'Username-Password-Authentication', strategy: 'auth0' }
export const eventTemplates: Record<string, Record<string, unknown>> = {
 'event-stream': { message: { id: 'evt_1234567890123456789012', specversion: '1.0', source: 'urn:sample', type: 'user.created', time: '2026-11-01T00:00:00Z', data: { object: { user_id: 'auth0|sample' } } }, secrets: {} },
 'post-login': { user, client, tenant, request, connection, transaction: { protocol: 'oidc-basic-profile', requested_scopes: ['openid', 'profile'] }, authorization: { roles: [] }, authentication: { methods: [] }, stats: { logins_count: 1 } },
 'credentials-exchange': { client, tenant, request, transaction: { protocol: 'oauth2-client-credentials', requested_scopes: [] }, resource_server: { identifier: 'https://api.example.test/' } },
 'pre-user-registration': { user: { email: user.email, user_metadata: {}, app_metadata: {} }, client, tenant, request, connection, transaction: { protocol: 'oauth2-password', requested_scopes: [] } },
 'post-user-registration': { user, tenant, request, connection },
 'post-change-password': { user, tenant, request, connection },
 'password-reset-post-challenge': { user, client, tenant, request, connection, transaction: { locale: 'en', correlation_id: '' } },
 'custom-email-provider': { user, client, tenant, request, notification: { from: 'sender@example.test', to: 'demo@example.test', subject: 'Sample verification', html: '<p>Sample email</p>', text: 'Sample email', locale: 'en', message_type: 'verify_email' } },
}

export const triggerHandlers: Record<string, string> = {
 'event-stream': 'onExecuteEventStream',
 'post-login': 'onExecutePostLogin', 'credentials-exchange': 'onExecuteCredentialsExchange', 'pre-user-registration': 'onExecutePreUserRegistration', 'post-user-registration': 'onExecutePostUserRegistration', 'post-change-password': 'onExecutePostChangePassword', 'password-reset-post-challenge': 'onExecutePostChallenge', 'custom-email-provider': 'onExecuteCustomEmailProvider',
}
export const triggerCode = (trigger: string) => trigger === 'event-stream' ? `exports.onExecuteEventStream = async (event, api) => {\n  const message = event.message;\n  const secrets = event.secrets;\n  const cache = api.cache;\n};\n` : `exports.${triggerHandlers[trigger]} = async (event, api) => {\n  // Add your Action here.\n};\n`
