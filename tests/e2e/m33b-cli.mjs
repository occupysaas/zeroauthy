// Plan 33b: pinned auth0-cli 1.37.0 raw `auth0 api` for the journey 10
// passkey operations, and the local SMTP / log-stream / event-stream receivers.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { appendFile, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { work, admin, capture, password, realm, sharedRP, softKey, softBody, receiverBearer } from "./m33b-node.mjs";

async function cli() {
  const home = `${work}/private-cli-home`;
  await mkdir(home, { recursive: true, mode: 0o700 });
  const env = {
    PATH: process.env.PATH,
    HOME: home,
    HTTPS_PROXY: "http://127.0.0.1:9198",
    SSL_CERT_FILE: process.env.E2E_CERT,
    AUTH0_CLI_ANALYTICS: "false",
    AUTH0_CLI_AUTH_MODE: "env",
    AUTH0_DOMAIN: "sdk.e2e.test",
    AUTH0_CLIENT_ID: admin.client,
    AUTH0_CLIENT_SECRET: admin.secret,
  };
  async function run(path, method = "GET", body, expectFailure = false) {
    const args = ["api", method, path, "--no-input", "--no-color", ...(method === "DELETE" ? ["--force"] : []), ...(body === undefined ? [] : ["--data", JSON.stringify(body)])];
    const r = spawnSync(process.env.AUTH0_BIN, args, { env, encoding: "utf8", timeout: 90000 });
    assert.ifError(r.error);
    await appendFile(`${work}/cli.jsonl`, JSON.stringify({ path, method, status: r.status, stdout: r.stdout, stderr: r.stderr }) + "\n");
    if (expectFailure) {
      assert.notEqual(r.status, 0, `${method} ${path} unexpectedly succeeded`);
      return r.stderr + r.stdout;
    }
    assert.equal(r.status, 0, `${method} ${path}: ${r.stderr}`);
    return r.stdout.trim() ? JSON.parse(r.stdout) : null;
  }
  const user = await run("users", "POST", { connection: realm, email: "cli-passkeys@e2e.local", password, email_verified: true });
  const path = `users/${encodeURIComponent(user.user_id)}/authentication-methods`;
  const key = softKey(sharedRP);
  const created = await run(path, "POST", softBody(key, { name: "CLI passkey" }));
  assert.equal(created.type, "passkey");
  await run(path, "POST", { type: "email", email: user.email });
  let list = await run(path);
  await capture("CLI list", list);
  const passkey = list.find((m) => m.type === "passkey");
  assert.equal(passkey.key_id, key.credId.toString("base64url"));
  assert.equal(passkey.relying_party_identifier, sharedRP);
  await run(`${path}/${encodeURIComponent(passkey.id)}`, "PATCH", { name: "CLI renamed" });
  assert.equal((await run(`${path}/${encodeURIComponent(passkey.id)}`)).name, "CLI renamed");
  await run(path, "DELETE");
  list = await run(path);
  assert.deepEqual(list.map((m) => m.type), ["passkey"], "bulk delete keeps passkeys");
  await run(`${path}/${encodeURIComponent(passkey.id)}`, "DELETE");
  assert.equal((await run(path)).length, 0);
  console.log("Plan33b auth0 CLI 1.37.0 raw passkey APIs passed (no native passkey command)");
}

async function receiver() {
  await mkdir(`${work}/private-mail`, { recursive: true, mode: 0o700 });
  const secureContext = tls.createSecureContext({ key: await readFile(process.env.E2E_KEY), cert: await readFile(process.env.E2E_CERT) });
  let n = Math.max(0, ...(await readdir(`${work}/private-mail`)).map((name) => parseInt(name, 10) || 0));
  net.createServer((socket) => {
    socket.write("220 local Plan33b SMTP\r\n");
    let buffer = "", data = false, message = [];
    const handle = async (chunk) => {
      buffer += chunk;
      let i;
      while ((i = buffer.indexOf("\r\n")) >= 0) {
        const line = buffer.slice(0, i);
        buffer = buffer.slice(i + 2);
        if (data) {
          if (line === ".") {
            data = false;
            await writeFile(`${work}/private-mail/${String(++n).padStart(6, "0")}.eml`, message.join("\n"), { mode: 0o600 });
            socket.write("250 queued\r\n");
          } else message.push(line);
          continue;
        }
        if (/^EHLO|^HELO/.test(line)) socket.write("250-local\r\n250 STARTTLS\r\n");
        else if (line === "STARTTLS") {
          socket.write("220 ready\r\n");
          socket.removeListener("data", handle);
          socket = new tls.TLSSocket(socket, { isServer: true, secureContext });
          socket.on("data", handle);
        } else if (/^DATA/.test(line)) {
          data = true;
          message = [];
          socket.write("354 continue\r\n");
        } else if (/^QUIT/.test(line)) socket.end("221 bye\r\n");
        else socket.write("250 ok\r\n");
      }
    };
    socket.on("data", handle);
  }).listen(9185, "127.0.0.1");
  https.createServer({ key: await readFile(process.env.E2E_KEY), cert: await readFile(process.env.E2E_CERT) }, async (req, res) => {
    if (req.url === "/events") assert.equal(req.headers.authorization, `Bearer ${receiverBearer}`);
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    await appendFile(`${work}/receiver.jsonl`, JSON.stringify({ path: req.url, body: Buffer.concat(chunks).toString() }) + "\n");
    res.writeHead(200).end("{}");
  }).listen(9186, "127.0.0.1");
  console.log("Plan33b SMTP and privacy receivers ready");
}

if (process.argv[1] === import.meta.filename)
  await ({ cli, receiver }[process.argv[2]] ?? (() => { throw Error("unknown mode"); }))();
