import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { appendFile, mkdir, writeFile, readdir } from "node:fs/promises";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { readFile } from "node:fs/promises";
import {
  work,
  credentials,
  capture,
  api,
  oneTime,
  password,
} from "./m33-mfa-node.mjs";
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
    AUTH0_CLIENT_ID: credentials.client,
    AUTH0_CLIENT_SECRET: credentials.secret,
  };
  async function run(path, method = "GET", body, allowed = []) {
    const args = [
      "api",
      method,
      path,
      "--no-input",
      "--no-color",
      ...(method.toUpperCase() === "DELETE" ? ["--force"] : []),
      ...(body === undefined ? [] : ["--data", JSON.stringify(body)]),
    ];
    const r = spawnSync(process.env.AUTH0_BIN, args, {
      env,
      encoding: "utf8",
      timeout: 90000,
    });
    assert.ifError(r.error);
    assert.equal(r.status, 0, `${method} ${path}: ${r.stderr}`);
    const value = r.stdout.trim() ? JSON.parse(r.stdout) : null;
    await appendFile(
      `${work}/cli.jsonl`,
      JSON.stringify({
        path,
        method,
        stdout: await oneTime(
          value,
          allowed,
          `CLI ${method.toUpperCase()} ${path}`,
        ),
        stderr: r.stderr,
      }) + "\n",
    );
    return value;
  }
  assert.deepEqual(await run("guardian/policies"), ["all-applications"]);
  const factors = await run("guardian/factors");
  assert.ok(factors.some((x) => x.name === "otp" && x.enabled));
  await run("guardian/factors/email", "PUT", { enabled: true });
  assert.equal(
    (await api("guardian/factors")).find((f) => f.name === "email").enabled,
    true,
  );
  await run("guardian/factors/email", "PUT", { enabled: false });
  await capture("CLI Guardian settings", await run("guardian/settings"));
  const user = await run("users", "POST", {
    connection: "Username-Password-Authentication",
    email: "cli-mfa@e2e.local",
    password,
    email_verified: true,
  });
  const path = `users/${encodeURIComponent(user.user_id)}`;
  const method = await run(`${path}/authentication-methods`, "POST", {
    type: "email",
    email: user.email,
  });
  assert.ok(
    (await run(`${path}/authentication-methods`)).some(
      (m) => m.id === method.id,
    ),
  );
  assert.equal(
    (
      await run(
        `${path}/authentication-methods/${encodeURIComponent(method.id)}`,
      )
    ).id,
    method.id,
  );
  await run(
    `${path}/authentication-methods/${encodeURIComponent(method.id)}`,
    "PATCH",
    { name: "CLI email" },
  );
  assert.ok((await run(`${path}/enrollments`)).length);
  const enrollment = method.id.split("|").at(-1);
  assert.equal(
    (await run(`guardian/enrollments/${enrollment}`)).id,
    enrollment,
  );
  const recovery = await run(`${path}/recovery-code-regeneration`, "POST", {}, [
    "recovery_code",
  ]);
  assert.match(recovery.recovery_code, /^[A-Z0-9]{24}$/);
  await run(`guardian/enrollments/${enrollment}`, "DELETE");
  await run(`${path}/authentication-methods`, "DELETE");
  assert.equal((await run(`${path}/authentication-methods`)).length, 0);
  console.log(
    "Plan33 auth0 CLI 1.37.0 raw Guardian APIs passed (no native Guardian command)",
  );
}
async function receiver() {
  await mkdir(`${work}/private-mail`, { recursive: true, mode: 0o700 });
  const secureContext = tls.createSecureContext({
    key: await readFile(process.env.E2E_KEY),
    cert: await readFile(process.env.E2E_CERT),
  });
  let n = Math.max(
    0,
    ...(await readdir(`${work}/private-mail`)).map(
      (name) => parseInt(name, 10) || 0,
    ),
  );
  net
    .createServer((socket) => {
      socket.write("220 local Plan33 SMTP\r\n");
      let buffer = "",
        data = false,
        message = [];
      const handle = async (chunk) => {
        buffer += chunk;
        let i;
        while ((i = buffer.indexOf("\r\n")) >= 0) {
          const line = buffer.slice(0, i);
          buffer = buffer.slice(i + 2);
          if (data) {
            if (line === ".") {
              data = false;
              await writeFile(
                `${work}/private-mail/${String(++n).padStart(6, "0")}.eml`,
                message.join("\n"),
                { mode: 0o600 },
              );
              socket.write("250 queued\r\n");
            } else message.push(line);
            continue;
          }
          if (/^EHLO|^HELO/.test(line))
            socket.write("250-local\r\n250 STARTTLS\r\n");
          else if (line === "STARTTLS") {
            socket.write("220 ready\r\n");
            socket.removeListener("data", handle);
            socket = new tls.TLSSocket(socket, {
              isServer: true,
              secureContext,
            });
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
    })
    .listen(9185, "127.0.0.1");
  https
    .createServer(
      {
        key: await readFile(process.env.E2E_KEY),
        cert: await readFile(process.env.E2E_CERT),
      },
      async (req, res) => {
        if (req.url === "/events")
          assert.equal(
            req.headers.authorization,
            "Bearer Plan33-Receiver-Bearer-2026",
          );
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        await appendFile(
          `${work}/receiver.jsonl`,
          JSON.stringify({
            path: req.url,
            body: Buffer.concat(chunks).toString(),
          }) + "\n",
        );
        res.writeHead(200).end("{}");
      },
    )
    .listen(9186, "127.0.0.1");
  console.log("Plan33 SMTP and privacy receivers ready");
}
if (process.argv[1] === import.meta.filename)
  await (
    { cli, receiver }[process.argv[2]] ??
    (() => {
      throw Error("unknown mode");
    })
  )();
