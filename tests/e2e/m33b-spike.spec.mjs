// Plan 33b Task 1 spike: can Chromium's CDP virtual authenticator run
// WebAuthn ceremonies against a self-signed *.e2e.test origin, and does a
// conditional (autofill) get resolve? Records which TLS mode works.
import { test, expect, chromium } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import https from 'node:https';

const host = 'spike.e2e.test';
let server, port, spki;

test.beforeAll(async () => {
  const dir = mkdtempSync(join(tmpdir(), 'm33b-spike-'));
  const key = join(dir, 'key.pem'), cert = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1',
    '-subj', `/CN=${host}`, '-addext', `subjectAltName=DNS:${host}`, '-keyout', key, '-out', cert], { stdio: 'ignore' });
  const pub = execFileSync('openssl', ['x509', '-in', cert, '-pubkey', '-noout']);
  const der = execFileSync('openssl', ['pkey', '-pubin', '-outform', 'der'], { input: pub });
  spki = execFileSync('openssl', ['dgst', '-sha256', '-binary'], { input: der }).toString('base64');
  const page = `<!doctype html><title>spike</title><input id="u" autocomplete="username webauthn">`;
  server = https.createServer({ key: readFileSync(key), cert: readFileSync(cert) }, (_, res) => {
    res.writeHead(200, { 'content-type': 'text/html' }); res.end(page);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  port = server.address().port;
  writeFileSync(join(dir, 'spki.txt'), spki);
});
test.afterAll(() => server?.close());

async function ceremonies(extraArgs) {
  const browser = await chromium.launch({
    executablePath: process.env.E2E_CHROMIUM || undefined,
    args: [`--host-resolver-rules=MAP ${host} 127.0.0.1`, ...extraArgs],
  });
  try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();
    await page.goto(`https://${host}:${port}/`);
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
      protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
    const out = await page.evaluate(async (rpId) => {
      const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));
      const result = {};
      try {
        await navigator.credentials.create({ publicKey: {
          challenge: rnd(32), rp: { id: rpId, name: rpId }, user: { id: rnd(32), name: 'spike', displayName: 'spike' },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          authenticatorSelection: { residentKey: 'required', userVerification: 'required' } } });
        result.create = 'ok';
      } catch (e) { result.create = e.name; return result; }
      try {
        await navigator.credentials.get({ publicKey: { challenge: rnd(32), rpId, userVerification: 'required' } });
        result.get = 'ok';
      } catch (e) { result.get = e.name; }
      result.conditionalAvailable = await PublicKeyCredential.isConditionalMediationAvailable?.() ?? false;
      const conditional = navigator.credentials.get({ mediation: 'conditional', publicKey: { challenge: rnd(32), rpId } })
        .then(() => 'ok', (e) => e.name);
      result.conditional = await Promise.race([conditional, new Promise((r) => setTimeout(() => r('pending'), 5000))]);
      return result;
    }, host);
    return out;
  } finally {
    await browser.close();
  }
}

test('virtual authenticator ceremonies on a self-signed e2e.test origin', async () => {
  const modes = [];
  let result = await ceremonies([]);
  modes.push({ mode: 'ignoreHTTPSErrors', ...result });
  if (result.create !== 'ok' || result.get !== 'ok') {
    result = await ceremonies([`--ignore-certificate-errors-spki-list=${spki}`]);
    modes.push({ mode: 'spki-list', ...result });
  }
  console.log('M33B_SPIKE ' + JSON.stringify(modes));
  expect(result.create).toBe('ok');
  expect(result.get).toBe('ok');
});
