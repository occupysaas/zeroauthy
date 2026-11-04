import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  appendFile,
  mkdir,
  writeFile,
  readdir,
  readFile,
} from "node:fs/promises";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { work, credentials, api, capture } from "./m34-node.mjs";
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
      socket.write("220 local Plan34 SMTP\r\n");
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
        if (req.url === "/events" || req.url === "/events-failure")
          assert.equal(
            req.headers.authorization,
            "Bearer Plan34-Receiver-Bearer-2026",
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
        res.writeHead(req.url === "/events-failure" ? 500 : 200).end("{}");
      },
    )
    .listen(9186, "127.0.0.1");
  console.log("Plan34 SMTP and privacy receivers ready");
}

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
  async function run(path, method = "GET", body) {
    const r = spawnSync(
      process.env.AUTH0_BIN,
      [
        "api",
        method,
        path,
        "--no-input",
        "--no-color",
        ...(method === "DELETE" ? ["--force"] : []),
        ...(body === undefined ? [] : ["--data", JSON.stringify(body)]),
      ],
      { env, encoding: "utf8", timeout: 90000 },
    );
    assert.ifError(r.error);
    assert.equal(r.status, 0, `${method} ${path}: ${r.stderr}`);
    const value = r.stdout.trim() ? JSON.parse(r.stdout) : null;
    await appendFile(
      `${work}/cli.jsonl`,
      JSON.stringify({ path, method, value, stderr: r.stderr }) + "\n",
    );
    return value;
  }
  const native = spawnSync(
    process.env.AUTH0_BIN,
    ["connections", "list", "--json", "--no-input", "--no-color"],
    { env, encoding: "utf8", timeout: 90000 },
  );
  assert.ifError(native.error);
  assert.equal(native.status, 0, native.stderr);
  const nativeConnections = JSON.parse(native.stdout);
  await appendFile(
    `${work}/cli.jsonl`,
    JSON.stringify({
      command: "connections list",
      value: nativeConnections,
      stderr: native.stderr,
    }) + "\n",
  );
  assert.ok(nativeConnections.some((c) => c.strategy === "email"));
  assert.ok(nativeConnections.some((c) => c.strategy === "sms"));
  const connections = await run("connections");
  assert.ok(connections.some((c) => c.strategy === "sms"));
  assert.ok(connections.some((c) => c.strategy === "email"));
  const providers = (await run("branding/phone/providers")).providers;
  assert.equal(providers.length, 1);
  await run("branding/phone/providers/" + providers[0].id, "PATCH", {
    disabled: false,
  });
  const templates = (await run("branding/phone/templates")).templates;
  assert.ok(templates.length);
  await run("guardian/factors/phone/message-types", "PUT", {
    message_types: ["sms", "voice"],
  });
  assert.deepEqual(
    (await run("guardian/factors/phone/message-types")).message_types,
    ["sms", "voice"],
  );
  await run("guardian/factors/phone/selected-provider", "PUT", {
    provider: "twilio",
  });
  await run("guardian/factors/phone/providers/twilio", "PUT", {
    sid: "AC34Guardian",
    auth_token: "Plan34-Guardian-Auth-Secret-2026",
    from: "+15550001111",
  });
  await run("guardian/factors/phone/providers/twilio");
  await run("guardian/factors/phone/templates", "PUT", {
    enrollment_message: "Code {{code}}",
    verification_message: "Code {{code}}",
  });
  await run("guardian/factors/phone/templates");
  await run("guardian/factors/phone/settings", "PUT", {
    otp_length: 6,
    otp_expiration_time: 300,
  });
  await run("guardian/factors/phone/settings");
  await run("attack-protection/phone-provider-protection", "PATCH", {
    type: "exponential",
  });
  assert.equal(
    (await run("attack-protection/phone-provider-protection")).type,
    "exponential",
  );
  await run("attack-protection/phone-provider-protection", "PATCH", {
    type: "default",
  });
  console.log(
    "Plan34 auth0 CLI 1.37.0 native connections + raw phone/Guardian/protection passed (no native phone commands)",
  );
}
if (process.argv[1] === import.meta.filename)
  await { receiver, cli }[process.argv[2]]();
