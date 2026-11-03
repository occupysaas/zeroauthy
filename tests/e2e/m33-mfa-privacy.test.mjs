import test from "node:test";
import assert from "node:assert/strict";
import { scan, totp, oneTime } from "./m33-mfa-node.mjs";

test("privacy scan rejects actual proof material in each captured sink and encoding", () => {
  const kinds = [
    "TOTP seed",
    "OTP",
    "email code",
    "recovery_code",
    "mfa_token",
    "ticket_id",
  ];
  const sinks = [
    "server.log",
    "receiver.jsonl",
    "browser-console.jsonl",
    "browser-responses.jsonl",
    "responses.jsonl",
    "cli.jsonl",
  ];
  for (const kind of kinds) {
    const value = `representative-${kind}-secret-value`;
    const transforms = [
      (v) => v,
      encodeURIComponent,
      (v) => Buffer.from(v).toString("base64"),
      (v) => Buffer.from(v).toString("base64url"),
      (v) => Buffer.from(v).toString("hex"),
    ];
    for (const sink of sinks)
      for (const transform of transforms) {
        assert.throws(
          () =>
            scan(
              JSON.stringify({ body: transform(value) }),
              [{ kind, value }],
              sink,
            ),
          /leaked/,
          `${sink}: ${kind} encoding`,
        );
      }
  }
  scan(
    '{"safe":"[REDACTED]"}',
    kinds.map((kind) => ({
      kind,
      value: `representative-${kind}-secret-value`,
    })),
    "clean sink",
  );
});

test("independent TOTP generator matches RFC6238 SHA1 vectors truncated to six digits", () => {
  const seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  for (const [time, expected] of [
    [59, "287082"],
    [1111111109, "081804"],
    [1111111111, "050471"],
    [1234567890, "005924"],
    [2000000000, "279037"],
    [20000000000, "353130"],
  ])
    assert.equal(totp(seed, Math.floor(time / 30)), expected);
});

test("one-time exceptions never apply to ordinary console or diagnostic responses", async () => {
  const material = {
    secret: "representative-TOTP-seed",
    description: "representative-TOTP-seed",
  };
  await assert.rejects(
    oneTime(material, ["secret"], "ordinary console response"),
    /exception not permitted/,
  );
  const captured = await oneTime(material, [], "ordinary console response");
  assert.deepEqual(captured, material);
  assert.throws(
    () =>
      scan(
        JSON.stringify(captured),
        [{ kind: "TOTP seed", value: material.secret }],
        "ordinary console response",
      ),
    /leaked/,
  );
});

test("mailbox waits for this delivery and cannot reuse an older code", async () => {
  const { mkdtemp, mkdir, writeFile, utimes, rm } = await import(
    "node:fs/promises"
  );
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = await mkdtemp(join(tmpdir(), "plan33-mailbox-"));
  const prior = process.env.E2E_M33_WORK;
  try {
    await mkdir(join(dir, "private-mail"));
    const old = join(dir, "private-mail", "999999.eml");
    await writeFile(old, "To: mailbox@e2e.local\nCode: 123456");
    await utimes(old, new Date(0), new Date(0));
    const before = new Set(["999999.eml"]);
    await writeFile(
      join(dir, "private-mail", "000001.eml"),
      "To: mailbox@e2e.local\nCode: 839472",
    );
    process.env.E2E_M33_WORK = dir;
    const { mailbox } = await import("./m33-mfa-node.mjs?mailbox-test");
    assert.equal(await mailbox("mailbox@e2e.local", before), "839472");
  } finally {
    if (prior === undefined) delete process.env.E2E_M33_WORK;
    else process.env.E2E_M33_WORK = prior;
    await rm(dir, { recursive: true, force: true });
  }
});
