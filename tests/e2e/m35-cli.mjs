// Plan 35: pinned auth0-cli 1.37.0 (token-exchange CRUD, apis --signing-alg;
// it has no command for client credentials, so those go through `auth0 api`),
// the pinned Deploy CLI 9.1.0 handlers run unmodified against this server
// (tokenExchangeProfiles, clients with token_exchange, clientAuthCredentials
// and its pre-pass), and the local log-stream receiver.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { appendFile, mkdir, readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import https from "node:https";
import { work, admin, api, raw, capture, state, token, fixtureFetch, redactText, authClient, decode, API, SUBJECT_TYPE } from "./m35-node.mjs";

async function cli() {
  const st = await state();
  const home = `${work}/private-cli-home`;
  await mkdir(home, { recursive: true, mode: 0o700 });
  const env = {
    PATH: process.env.PATH,
    HOME: home,
    HTTPS_PROXY: "http://127.0.0.1:9198",
    SSL_CERT_FILE: process.env.E2E_CERT,
    AUTH0_CLI_ANALYTICS: "false",
    AUTH0_AGENT_MODE: "false",
    AUTH0_CLI_AUTH_MODE: "env",
    AUTH0_DOMAIN: "sdk.e2e.test",
    AUTH0_CLIENT_ID: admin.client,
    AUTH0_CLIENT_SECRET: admin.secret,
  };
  function run(args, expectFailure = false) {
    const r = spawnSync(process.env.AUTH0_BIN, [...args, "--no-input", "--no-color"], { env, encoding: "utf8", timeout: 90000 });
    assert.ifError(r.error);
    return appendFile(`${work}/cli.jsonl`, JSON.stringify({ args, status: r.status, stdout: redactText(r.stdout), stderr: r.stderr }) + "\n").then(() => {
      if (expectFailure) {
        assert.notEqual(r.status, 0, `${args.join(" ")} unexpectedly succeeded`);
        return r.stderr + r.stdout;
      }
      assert.equal(r.status, 0, `${args.join(" ")}: ${r.stderr}`);
      return r.stdout.trim() ? JSON.parse(r.stdout) : null;
    });
  }
  // Token exchange profiles: the CLI's own commands.
  let list = await run(["token-exchange", "list", "--json"]);
  assert.ok(list.some((p) => p.subject_token_type === SUBJECT_TYPE), "CLI lists the setup profile");
  const made = await run(["token-exchange", "create", "-n", "Plan35 CLI profile", "-s", "urn:plan35:cli-token", "-a", st.action.id, "-t", "custom_authentication", "--json"]);
  assert.match(made.id, /^tep_[0-9A-Za-z]{22}$/);
  assert.equal((await run(["token-exchange", "show", made.id, "--json"])).subject_token_type, "urn:plan35:cli-token");
  await run(["token-exchange", "update", made.id, "-n", "Plan35 CLI renamed", "--json"]);
  assert.equal((await run(["token-exchange", "show", made.id, "--json"])).name, "Plan35 CLI renamed");
  await run(["token-exchange", "delete", made.id, "--force"]);
  list = await run(["token-exchange", "list", "--json"]);
  assert.ok(!(list ?? []).some((p) => p.id === made.id), "CLI delete removed the profile");
  // API signing algorithms: apis create/update --signing-alg.
  const created = await run(["apis", "create", "-n", "Plan35 CLI API", "-i", "https://cli.m35.e2e.test", "--signing-alg", "PS256", "--json"]);
  assert.equal(created.signing_alg, "PS256");
  const updated = await run(["apis", "update", created.id, "--signing-alg", "HS256", "--json"]);
  assert.equal(updated.signing_alg, "HS256");
  const shown = await run(["apis", "show", created.id, "--json"]);
  assert.equal(shown.signing_alg, "HS256");
  assert.equal(typeof shown.signing_secret, "string", "HS256 secret generated on the switch (LR35-8)");
  await run(["apis", "update", created.id, "--signing-alg", "RS256", "--json"]);
  assert.equal((await api(`resource-servers/${created.id}`)).signing_secret, undefined, "moving away from HS256 discards the secret");
  await run(["apis", "delete", created.id, "--force"]);
  // Client credentials: no CLI command in 1.37.0, so the raw `auth0 api`.
  const creds = await run(["api", "get", "clients/m35-backend/credentials"]);
  assert.deepEqual(creds.map((c) => c.name), ["backend-b"]);
  assert.ok(creds.every((c) => c.pem === undefined));
  console.log("Plan35 auth0 CLI 1.37.0: token-exchange list/create/show/update/delete, apis --signing-alg PS256/HS256/RS256, raw credentials read passed (no credentials command)");
}

async function deploy() {
  // The pinned Deploy CLI handlers, unmodified, with the pinned SDK's paged
  // client against this server.
  const st = await state();
  const require = createRequire(import.meta.url);
  const modules = new URL("./node_modules/", import.meta.url).pathname;
  assert.equal(require(`${modules}auth0-deploy-cli/package.json`).version, "9.1.0");
  const { ManagementClient: CJSClient } = require(`${modules}auth0`);
  const tools = `${modules}auth0-deploy-cli/lib/tools/auth0`;
  const client = require(`${tools}/client`).default(new CJSClient({ domain: "sdk.e2e.test", token: await token(), maxRetries: 0, fetch: fixtureFetch }));
  const make = (name, allowDelete = false) => new (require(`${tools}/handlers/${name}`).default)({ client, config: (k) => (k === "AUTH0_ALLOW_DELETE" ? allowDelete : false) });
  const pick = (rows, k, v) => rows.find((row) => row[k] === v);

  // tokenExchangeProfiles: an Action is named, the export maps action_id back
  // to the name, a profile is matched by subject_token_type.
  const deployType = "urn:plan35:deploy-token";
  await make("tokenExchangeProfiles").processChanges({ tokenExchangeProfiles: [{ name: "Plan35 deploy profile", subject_token_type: deployType, action: st.action.name, type: "custom_authentication" }] });
  let rows = await make("tokenExchangeProfiles").getType();
  await capture("deploy profiles export", rows);
  let row = pick(rows, "subject_token_type", deployType);
  assert.ok(row, "the imported profile is exported");
  assert.equal(row.action, st.action.name);
  assert.equal(row.action_id, undefined);
  assert.ok(pick(rows, "subject_token_type", SUBJECT_TYPE), "the existing profile is exported too");
  await make("tokenExchangeProfiles").processChanges({ tokenExchangeProfiles: rows.map((r) => (r.subject_token_type === deployType ? { ...r, name: "Plan35 deploy renamed" } : r)) });
  rows = await make("tokenExchangeProfiles").getType();
  row = pick(rows, "subject_token_type", deployType);
  assert.equal(row.name, "Plan35 deploy renamed");
  // The handler PATCHes every matched profile; an unchanged re-import must
  // leave everything but the update timestamp as it was.
  const content = (list) => JSON.stringify(list.map(({ updated_at, ...rest }) => rest));
  const before = content(rows);
  await make("tokenExchangeProfiles").processChanges({ tokenExchangeProfiles: structuredClone(rows) });
  assert.equal(content(await make("tokenExchangeProfiles").getType()), before, "an unchanged re-import changes no profile");
  await make("tokenExchangeProfiles", true).processChanges({ tokenExchangeProfiles: rows.filter((r) => r.subject_token_type !== deployType) });
  rows = await make("tokenExchangeProfiles").getType();
  assert.equal(pick(rows, "subject_token_type", deployType), undefined, "AUTH0_ALLOW_DELETE removed the profile");
  assert.ok(pick(rows, "subject_token_type", SUBJECT_TYPE), "the other profile stays");

  // clients + clientAuthCredentials: the PEM in client_authentication_methods
  // creates a credential, which is then wired into the client.
  const name = "Plan35 Deploy Keys";
  const desired = (key, keyName, alg) => ({
    name,
    app_type: "regular_web",
    is_first_party: true,
    grant_types: ["client_credentials"],
    token_exchange: { allow_any_profile_of_type: ["custom_authentication"] },
    client_authentication_methods: { private_key_jwt: { credentials: [{ name: keyName, pem: key.spki, alg }] } },
  });
  let assets = { clients: [desired(st.keys.deploy1, "deploy-key-1", "RS256")] };
  await make("clientAuthCredentialsPre").processChanges(assets);
  await make("clients").processChanges(assets);
  await make("clientAuthCredentials").processChanges(assets);
  let exported = pick(await make("clients").getType(), "name", name);
  assert.ok(exported, "deploy created the client");
  const id = exported.client_id;
  assert.deepEqual(exported.token_exchange, { allow_any_profile_of_type: ["custom_authentication"] });
  assert.deepEqual(exported.client_authentication_methods, { private_key_jwt: { credentials: [{ name: "deploy-key-1", credential_type: "public_key" }] } }, "export carries credential names, never the PEM");
  let creds = await api(`clients/${id}/credentials`);
  assert.deepEqual(creds.map((c) => [c.name, c.alg]), [["deploy-key-1", "RS256"]]);
  const first = creds[0].id;
  await api("client-grants", "POST", { client_id: id, audience: API, scope: ["read:things"] });
  const viaKey = (key, alg) => authClient(id, { clientAssertionSigningKey: key.pkcs8, clientAssertionSigningAlg: alg }).getTokenByClientCredentials({ audience: API });
  assert.equal(decode((await viaKey(st.keys.deploy1, "RS256")).accessToken).claims.azp, id);
  // Re-importing the export (no PEM) leaves the credential alone.
  await make("clientAuthCredentials").processChanges({ clients: [structuredClone(exported)] });
  assert.deepEqual((await api(`clients/${id}/credentials`)).map((c) => c.id), [first]);
  // Rotation: a new PEM under a new name; with AUTH0_ALLOW_DELETE the old
  // key is removed after the client is rewired.
  assets = { clients: [{ ...desired(st.keys.deploy2, "deploy-key-2", "PS256"), client_id: id }] };
  await make("clientAuthCredentials", true).processChanges(assets);
  creds = await api(`clients/${id}/credentials`);
  assert.deepEqual(creds.map((c) => [c.name, c.alg]), [["deploy-key-2", "PS256"]]);
  assert.deepEqual((await api(`clients/${id}`)).client_authentication_methods.private_key_jwt.credentials.map((c) => c.id), [creds[0].id]);
  assert.equal(decode((await viaKey(st.keys.deploy2, "PS256")).accessToken).claims.azp, id);
  await assert.rejects(viaKey(st.keys.deploy1, "RS256"), "the rotated-out key no longer authenticates");
  // The pre-pass: a client without the field loses its keys and goes back to a secret.
  await make("clientAuthCredentialsPre", true).processChanges({ clients: [{ name, client_id: id }] });
  assert.deepEqual(await api(`clients/${id}/credentials`), []);
  const after = await api(`clients/${id}`);
  assert.equal(after.client_authentication_methods ?? null, null);
  assert.equal(after.token_endpoint_auth_method, "client_secret_post");
  await raw(`clients/${id}`, "DELETE");
  console.log(`Plan35 Deploy CLI 9.1.0 handlers (tokenExchangeProfiles, clients token_exchange, clientAuthCredentials + pre-pass) passed on ${process.env.E2E_M35_BACKEND}`);
}

async function receiver() {
  https
    .createServer({ key: await readFile(process.env.E2E_KEY), cert: await readFile(process.env.E2E_CERT) }, async (req, res) => {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      await appendFile(`${work}/receiver.jsonl`, JSON.stringify({ path: req.url, body: Buffer.concat(chunks).toString() }) + "\n");
      res.writeHead(200).end("{}");
    })
    .listen(9186, "127.0.0.1");
  console.log("Plan35 log-stream receiver ready");
}

if (process.argv[1] === import.meta.filename)
  await ({ cli, deploy, receiver }[process.argv[2]] ?? (() => { throw Error("unknown mode"); }))();
