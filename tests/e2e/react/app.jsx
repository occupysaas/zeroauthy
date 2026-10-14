// tests/e2e/react/app.jsx: a minimal app using @auth0/auth0-react as its
// public README shows. Only the domain points at zeroauthy.
import React from 'react';
import { createRoot } from 'react-dom/client';
import { Auth0Provider, useAuth0 } from '@auth0/auth0-react';

const home = window.location.origin + '/react/';

function App() {
  const auth = useAuth0();
  // Expose the hook's public API to the Playwright test.
  window.__za = auth;
  if (auth.isLoading) return <p>Loading</p>;
  if (auth.error) return <p id="error" data-ready="error">{auth.error.message}</p>;
  if (!auth.isAuthenticated) {
    return <button id="login" data-ready="true" onClick={() => auth.loginWithRedirect()}>Log in</button>;
  }
  return (
    <div data-ready="true">
      <p id="email">{auth.user.email}</p>
      <button id="logout" onClick={() => auth.logout({ logoutParams: { returnTo: home } })}>Log out</button>
    </div>
  );
}

createRoot(document.getElementById('root')).render(
  <Auth0Provider
    domain="localhost:8443"
    clientId="e2e-react"
    useRefreshTokens
    cacheLocation="localstorage"
    authorizationParams={{ redirect_uri: home, audience: 'https://api.e2e.local', scope: 'openid profile email read:things' }}
  >
    <App />
  </Auth0Provider>,
);
