import { test } from "node:test";
import assert from "node:assert/strict";
import { privacyScan } from "./m34-node.mjs";
test("every sink rejects actual OTP, encoded links, provider credentials and full recipient numbers", () => {
  const values = [
    { kind: "phone OTP", value: "381729" },
    { kind: "link token", value: "plan34-actual-link-proof" },
    { kind: "provider credential", value: "plan34-actual-provider-secret" },
    { kind: "phone number", value: "+14155553412" },
  ];
  for (const label of [
    "server.log",
    "responses.jsonl",
    "cli.jsonl",
    "receiver.jsonl",
    "stored-sinks.jsonl",
    "browser-responses.jsonl",
  ]) {
    for (const s of values)
      for (const encoded of [
        s.value,
        encodeURIComponent(s.value),
        Buffer.from(s.value).toString("base64"),
        Buffer.from(s.value).toString("hex"),
        Buffer.from(s.value).toString("base64url"),
      ])
        assert.throws(
          () => privacyScan(JSON.stringify({ data: encoded }), values, label),
          /leaked/,
        );
    assert.throws(() => privacyScan("3. 8. 1. 7. 2. 9", values, label));
    assert.doesNotThrow(() =>
      privacyScan('"phone_number":"XXXXXXXX3412"', values, label),
    );
  }
});
