// Configured from AUTH0_* and APP_BASE_URL environment variables set by
// run-browser.sh, as the SDK's README describes.
//
// The SDK refuses a bare `localhost:8443` domain ("Domain cannot contain
// ports") and rejects localhost unless `allowInsecureRequests` is set, so
// run-browser.sh passes AUTH0_DOMAIN with its scheme and this enables the
// option. Requests to zeroauthy still go over https; NODE_EXTRA_CA_CERTS
// supplies the test certificate.
import { Auth0Client } from '@auth0/nextjs-auth0/server';

export const auth0 = new Auth0Client({
  allowInsecureRequests: true,
  // run-browser.sh starts a second instance with E2E_PAR=1 for m10-par.
  pushedAuthorizationRequests: process.env.E2E_PAR === '1',
  authorizationParameters: {
    audience: 'https://api.e2e.local',
    scope: 'openid profile email offline_access read:things',
  },
});
