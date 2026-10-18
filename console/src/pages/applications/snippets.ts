// The ready-to-copy snippets of an application's quick-start panel. They
// are pure functions of the tenant's host and the application, so the
// tests can pin each one.
//
// host is SystemTenant.host: the tenant's canonical host, the way the
// server writes it (tenant.ManagementAPIIdentifier in Go): lower-case, with
// the port only when it is not 443. Every URL here is https://<host>/...,
// which is the issuer of the tokens the tenant mints (issuer = that URL
// plus a trailing slash).

export const SECRET_PLACEHOLDER = 'YOUR_CLIENT_SECRET'
export const AUDIENCE_PLACEHOLDER = 'YOUR_API_IDENTIFIER'
export const CALLBACK_PLACEHOLDER = 'https://YOUR_APP/callback'

export interface AppFacts {
  host: string
  clientID: string
  // authMethod is the application's token_endpoint_auth_method.
  authMethod: string
  callbacks: string[]
}

// shQuote quotes s as one word for a POSIX shell.
export function shQuote(s: string): string {
  return "'" + s.replace(/'/g, `'\\''`) + "'"
}

// jsString writes s as a single-quoted JavaScript string literal.
function jsString(s: string): string {
  return "'" + s.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n') + "'"
}

export function origin(host: string): string {
  return 'https://' + host
}

export function firstCallback(callbacks: string[]): string {
  return callbacks[0] ?? CALLBACK_PLACEHOLDER
}

// tokenCurl asks the token endpoint for an access token for audience with
// the client credentials grant. secret is the client secret, or null while
// it is not revealed (then a placeholder stands in).
export function tokenCurl(a: AppFacts, audience: string, secret: string | null): string {
  const lines = [`curl --request POST --url ${shQuote(origin(a.host) + '/oauth/token')}`, `  --header 'content-type: application/x-www-form-urlencoded'`, `  --data grant_type=client_credentials`]
  const s = secret ?? SECRET_PLACEHOLDER
  if (a.authMethod === 'client_secret_basic') {
    lines.push(`  --user ${shQuote(a.clientID + ':' + s)}`)
  } else {
    lines.push(`  --data-urlencode ${shQuote('client_id=' + a.clientID)}`)
    if (a.authMethod !== 'none') lines.push(`  --data-urlencode ${shQuote('client_secret=' + s)}`)
  }
  lines.push(`  --data-urlencode ${shQuote('audience=' + audience)}`)
  return lines.join(' \\\n')
}

// callCurl calls the API with the access token the call above returned.
export function callCurl(audience: string): string {
  return [`curl --url ${shQuote(audience)}`, `  --header 'authorization: Bearer ACCESS_TOKEN'`].join(' \\\n')
}

const enc = encodeURIComponent

// authorizeURL is where a browser or native app starts the authorization
// code flow with PKCE.
export function authorizeURL(a: AppFacts): string {
  const q: [string, string][] = [
    ['response_type', 'code'],
    ['client_id', a.clientID],
    ['redirect_uri', firstCallback(a.callbacks)],
    ['scope', 'openid profile email'],
    ['audience', AUDIENCE_PLACEHOLDER],
    ['state', 'STATE'],
    ['code_challenge', 'CODE_CHALLENGE'],
    ['code_challenge_method', 'S256'],
  ]
  return origin(a.host) + '/authorize?' + q.map(([k, v]) => `${k}=${enc(v)}`).join('&')
}

// The option names below are those of the SDKs' public documentation.

export function spaJS(a: AppFacts): string {
  return [
    `import { createAuth0Client } from '@auth0/auth0-spa-js'`,
    ``,
    `const auth0 = await createAuth0Client({`,
    `  domain: ${jsString(a.host)},`,
    `  clientId: ${jsString(a.clientID)},`,
    `  authorizationParams: {`,
    `    redirect_uri: ${jsString(firstCallback(a.callbacks))},`,
    `    audience: ${jsString(AUDIENCE_PLACEHOLDER)},`,
    `  },`,
    `})`,
  ].join('\n')
}

export function spaReact(a: AppFacts): string {
  return [
    `import { Auth0Provider } from '@auth0/auth0-react'`,
    ``,
    `<Auth0Provider`,
    `  domain=${'{'}${jsString(a.host)}${'}'}`,
    `  clientId=${'{'}${jsString(a.clientID)}${'}'}`,
    `  authorizationParams=${'{{'}`,
    `    redirect_uri: ${jsString(firstCallback(a.callbacks))},`,
    `    audience: ${jsString(AUDIENCE_PLACEHOLDER)},`,
    `  ${'}}'}`,
    `>`,
    `  <App />`,
    `</Auth0Provider>`,
  ].join('\n')
}

// nextjsEnv is the .env.local of nextjs-auth0.
export function nextjsEnv(a: AppFacts, secret: string | null): string {
  return [
    `AUTH0_DOMAIN=${a.host}`,
    `AUTH0_CLIENT_ID=${a.clientID}`,
    `AUTH0_CLIENT_SECRET=${secret ?? SECRET_PLACEHOLDER}`,
    `AUTH0_SECRET=A_LONG_RANDOM_STRING`,
    `APP_BASE_URL=http://localhost:3000`,
  ].join('\n')
}

// expressConfig configures express-openid-connect.
export function expressConfig(a: AppFacts, secret: string | null): string {
  return [
    `import { auth } from 'express-openid-connect'`,
    ``,
    `app.use(`,
    `  auth({`,
    `    issuerBaseURL: ${jsString(origin(a.host))},`,
    `    baseURL: 'http://localhost:3000',`,
    `    clientID: ${jsString(a.clientID)},`,
    `    clientSecret: ${jsString(secret ?? SECRET_PLACEHOLDER)},`,
    `    secret: 'A_LONG_RANDOM_STRING',`,
    `    authRequired: false,`,
    `    authorizationParams: {`,
    `      response_type: 'code',`,
    `      audience: ${jsString(AUDIENCE_PLACEHOLDER)},`,
    `    },`,
    `  }),`,
    `)`,
  ].join('\n')
}
