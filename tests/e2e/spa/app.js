// tests/e2e/spa/app.js — a minimal app using auth0-spa-js exactly as its
// public README shows; only the domain points at zeroauthy.
(async () => {
  const base = ['/confirm/', '/strict/'].find((p) => window.location.pathname.startsWith(p)) || '/';
  if (base === '/strict/') {
    document.body.dataset.ready = 'true';
    return;
  }
  const started = performance.now();
  const client = await auth0.createAuth0Client({
    domain: 'localhost:8443',
    clientId: base === '/confirm/' ? 'e2e-confirm' : 'e2e-spa',
    authorizationParams: {
      redirect_uri: window.location.origin + base,
      audience: 'https://api.e2e.local',
      scope: 'openid profile email read:things',
    },
  });
  const initMs = performance.now() - started;
  const params = new URLSearchParams(window.location.search);
  if (params.has('code') && params.has('state')) {
    await client.handleRedirectCallback();
    window.history.replaceState({}, '', base);
  }
  window.__za = { client, initMs };
  document.getElementById('login').onclick = () => client.loginWithRedirect();
  document.body.dataset.ready = 'true';
})().catch((err) => {
  document.getElementById('out').textContent = String((err && (err.error_description || err.error || err.message)) || err);
  document.body.dataset.ready = 'error';
});
