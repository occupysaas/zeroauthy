# Plan 45a — Security hardening (key hierarchy and rotation, customer-managed keys, runner sandbox, transport defaults)

**Date:** 2026-11-16. **Status:** design; not implemented; needs maintainer
rulings (§9) before the parts they gate.

**Roadmap entry:** [management roadmap, Plan 45](2026-10-19-zeroauthy-management-roadmap-design.md)
(pre-1.0 review deferrals); [parallel paths](2026-11-13-zeroauthy-parallel-paths-design.md)
item **O2** (track O, independent). Plan 38d (M1) moved
`/api/v2/keys/encryption*` here (LR38d-1). Read the
[clean-room policy](../../../CLEAN_ROOM.md), `AGENTS.md`, `SECURITY.md`,
D-0022 (custom database sandbox), D-0053/D-0054 (Actions trust domain),
the [pre-1.0 review](../reviews/2026-11-03-pre-1.0/) and memory notes
"Actions tenant trust domain" and "Secrets never in logs".

Not to be confused with open PR #16 (CI supply-chain hardening: pinned
actions, Dependabot, Scorecard, fuzzing). That PR changes workflows; this
plan changes the server. Neither blocks the other.

## 1. Outcome and scope

Three independent parts:

**A. Key hierarchy, rotation and customer-managed keys.** Every sealed value
(client secrets, connection credentials, Action and module secrets,
provider credentials, upstream tokens, TOTP secrets, signing keys, …) moves
to a versioned envelope with a per-tenant master key. Operators rotate the
server root key without downtime, rekey a tenant, and — through Auth0's
`/api/v2/keys/encryption*` API — bring their own tenant root key.

**B. Runner sandbox.** The Node processes that run Actions and custom
database scripts gain OS-level confinement on Linux on top of Node's
permission model, share one prelude, and are retired (not muted) when their
log-capture or secret-mask budget is spent.

**C. Transport and logging defaults.** HSTS when zeroauthy terminates TLS,
database TLS checks, and scrubbing of plugin stderr.

**Rule:** Part A's API is strict 1:1 with Auth0's documented behaviour
(memory: Auth0 parity first); parts B and C are zeroauthy internals with no
Auth0 surface. Local rulings **LR45a-n** and observation points **K1–Kn**
go in **D-0260** (O2 block D-0260–0269).

### In scope

1. Envelope v2 and the key hierarchy (§3).
2. Root-key rotation with previous keys and a background rewrap (§4).
3. `/api/v2/keys/encryption*` (§5): list, get, create (pre-activation
   customer-provided root key), wrapping key, import, rekey, delete.
4. Linux sandbox for runner processes (§6.1), shared prelude (§6.2),
   retirement on spent budgets (§6.3).
5. HSTS (§7.1), database TLS (§7.2), plugin stderr scrubbing (§7.3).

### Not in scope

- An external KMS (AWS KMS, GCP KMS, Vault) as the root: the `Wrapper`
  interface allows it later; not built (decision §9.4).
- Sandboxing on macOS/Windows beyond Node's permission model.
- Hardware-backed keys.

### Anti-goals

- **Downtime or lockout during rotation.** Every value stays readable
  throughout: v1 envelopes keep working; a v2 envelope names the key that
  wraps it; previous root keys stay configured until the rewrap job
  reports zero remaining references.
- **A deleted customer key destroying data silently.** `DELETE
  /keys/encryption/{kid}` of an active customer-provided root key first
  rewraps the tenant master key under the native root, then deactivates
  (documented "move back to using native encryption key").
- **Key material in logs or API responses.** Root keys, tenant master keys
  and imported key material never appear in logs, responses (only public
  wrapping keys do), seed exports or Deploy CLI.
- **A sandbox that silently degrades.** If the sandbox cannot be applied on
  Linux (old kernel without Landlock), the runner refuses to start unless
  the operator sets an explicit opt-out (decision §9.2), and the console
  shows the state.

## 2. Evidence

- Management OpenAPI (read 2026-11-16): `get_encryption-keys`,
  `post_encryption-keys` (body `type`; "pre-activated encryption key,
  without the key material"), `post_rekey` (scopes `create:` +
  `update:encryption_keys`; "rekeying operation on the key hierarchy"),
  `get/delete_encryption-key` (delete: "Delete the custom provided
  encryption key with the given ID and move back to using native
  encryption key"), `post_encryption-key` (import: `wrapped_key` base64
  ciphertext "wrapped by public wrapping key"), `post_wrapping-key`
  (`public_key`, `algorithm`); key object `kid`, `type`, `state`,
  `created_at`, `updated_at`, `parent_kid`, `public_key`; types
  `customer-provided-root-key`, `environment-root-key`,
  `tenant-master-key`, `tenant-encryption-key`; states `pre-activation`,
  `active`, `deactivated`, `destroyed`.
- Auth0 BYOK docs (`/docs/secure/highly-regulated-identity/customer-managed-keys`,
  read at build time for the wrapping algorithm and key format, K1).
- Linux Landlock (kernel ≥ 5.13) and seccomp via `golang.org/x/sys/unix`
  (already in `go.mod`, v0.49.0); RFC 6797 (HSTS).

## 3. Envelope v2 and hierarchy

```
root key (server: ZEROAUTHY_SECURITY__MASTER_KEY, or a tenant's customer-provided root)
  └─ tenant master key (TMK, one active per tenant, 32 random bytes)
       └─ record DEK (per sealed value, as today)
```

- v2 envelope: `{"v":2,"tmk":"<tmk kid>","dek":<DEK wrapped by TMK>,"ct":...}`;
  AAD unchanged (each caller's binding).
- TMK records `tenant_master_keys(tenant_id, kid, state, wrapped_by
  (root kid), wrapped, created_at, …)`; the active TMK seals new values;
  older TMKs stay to unseal.
- Root keys have a kid = first 16 hex chars of SHA-256 of the key (LR45a-1).
- System tenant values use the same scheme with the system tenant's TMK.
- Every `keys.Seal*` helper keeps its signature; the change sits in
  `envelope.go` and a tenant-aware `Wrapper` resolved per call from the
  tenant ID already in each helper's AAD inputs. Helpers that wrap without
  an envelope (inventoried in Task 1) move onto it.
- v1 envelopes are read forever; the rewrap job converts them.

## 4. Root-key rotation

- Configuration: `ZEROAUTHY_SECURITY__MASTER_KEY(_FILE)` is the current root;
  new `ZEROAUTHY_SECURITY__PREVIOUS_MASTER_KEYS_FILE` lists retired roots
  (one base64 key per line).
- On start, TMKs wrapped by a previous root are rewrapped under the current
  root (cheap: one per tenant), in batches, idempotent, logged with counts.
- `zeroauthy keys rewrap` (CLI) converts remaining v1 envelopes to v2 and
  reports remaining references per root kid; `zeroauthy keys status` prints
  them. The operator removes a previous root only when its count is zero
  (the server refuses to start if a referenced root is missing, naming the
  kid, LR45a-2).
- Multi-replica: rewrap uses compare-and-swap on each row, so concurrent
  replicas never double-wrap.

## 5. Customer-managed keys API

| Operation | zeroauthy behaviour |
|---|---|
| `GET /keys/encryption` | the tenant's hierarchy: one `environment-root-key` (the server root, `parent_kid` null), the tenant's `tenant-master-key`(s) (`parent_kid` = root kid), a `tenant-encryption-key` entry representing the DEK layer (`parent_kid` = TMK; K2), and any `customer-provided-root-key` |
| `POST /keys/encryption {type: customer-provided-root-key}` | creates a `pre-activation` key record; one at a time (`409`, K3) |
| `POST /keys/encryption/{kid}/wrapping-key` | creates an RSA-3072 wrapping key pair for that record; returns `public_key` (PEM) and `algorithm` (`CKM_RSA_AES_KEY_WRAP`, K1); private part sealed under the server root |
| `POST /keys/encryption/{kid} {wrapped_key}` | unwraps the imported 32-byte key with the wrapping private key, activates it, rewraps the tenant's active TMK under it; the server root no longer unwraps that tenant's TMK (LR45a-3) |
| `POST /keys/encryption/rekey` | new TMK; the rewrap job moves that tenant's DEKs to it; old TMK `deactivated` when none remain, then `destroyed` (LR45a-4) |
| `DELETE /keys/encryption/{kid}` | customer-provided root: rewrap TMKs under the server root, mark `destroyed`; other types `400` |

- Losing a customer-provided root key that was deleted outside zeroauthy is
  impossible to recover from by design (documented in the guide, as Auth0
  warns).
- The hosted product (X1) is the main user; self-hosted operators already
  own the server root.

## 6. Runners

### 6.1 Linux sandbox

Applied in the child before `exec` of `node` (a small re-exec helper of the
`zeroauthy` binary, so no new binary ships):

- `PR_SET_NO_NEW_PRIVS`.
- **Landlock** (ABI ≥ 1): read-only access to the Node installation and the
  per-tenant script directory, read-write only to the per-process temp
  directory; nothing else.
- **seccomp** filter (allowlist built for Node 25 on amd64/arm64): denies
  `ptrace`, `mount`, `bpf`, `keyctl`, `perf_event_open`, namespace and
  module syscalls, raw sockets (`socket(AF_PACKET|AF_NETLINK)`), and
  `execve` after start (no child processes; Node's `child_process` is
  already blocked by the permission model — defence in depth).
- **rlimits:** address space (from the existing heap limit + margin),
  `RLIMIT_NOFILE` 256, `RLIMIT_NPROC` 1 (threads are allowed through
  `clone` flags check), `RLIMIT_CORE` 0.
- Network stays allowed (Actions may call external HTTP, as on Auth0), but
  the existing outbound policy (no loopback, no private ranges, no unix
  sockets) moves from JS hooks into the seccomp/`connect` check where the
  kernel can enforce it (LR45a-5; K4: feasibility of address filtering in
  seccomp without a user-space notifier — fallback keeps the JS guard).
- A startup self-test spawns a probe that must fail to read `/etc/hostname`
  and to open a raw socket; failure → refuse to start or warn (§9.2).

### 6.2 Shared prelude

`internal/noderunner/guard.mjs` and `internal/customdb/runner.mjs` share one
prelude module (environment scrub, `require` allowlist, fetch guard, log
capture and masking), loaded by both; tests run the same probe suite
against both runners.

### 6.3 Retirement on spent budgets

When a tenant process exhausts its log-capture window or its secret-mask
table capacity, it is retired (finishes in-flight calls, takes no new ones,
a fresh process starts on the next call) instead of continuing with logging
muted (pre-1.0 review finding).

## 7. Transport and logs

### 7.1 HSTS

`Strict-Transport-Security: max-age=31536000` on HTTPS responses that
zeroauthy itself terminates (custom-domain ACME listener, configured TLS
listener). Not sent behind a TLS-terminating proxy unless the operator sets
`ZEROAUTHY_SERVER__HSTS=true` (the proxy owns the policy). `includeSubDomains`
and `preload` only by explicit configuration (LR45a-6).

### 7.2 Database TLS

- PostgreSQL DSNs without `sslmode`, or with `disable`/`allow`/`prefer`,
  and MySQL DSNs without `tls=`: startup warning naming the risk, unless
  the host is loopback or a unix socket.
- `ZEROAUTHY_STORAGE__REQUIRE_TLS=true` turns the warning into a refusal
  (default `false` in 1.x; decision §9.3 on making it the default later).

### 7.3 Plugin stderr

gRPC storage plugins' stderr lines pass through the existing key-name and
value scrubber (`internal/logscrub`) before reaching the server log, with a
line-length cap (8 KiB) and a rate limit.

## 8. Storage, console, tests

- **Storage:** `tenant_master_keys`, `customer_root_keys` (records,
  wrapping key pairs sealed under the server root); sealed columns
  unchanged in type (blobs); one migration numbered at merge. gRPC plugins:
  envelopes are opaque bytes, so plugins need only the two new tables
  (capability `key_hierarchy.v1`; without it v1 envelopes stay in use and
  the keys API answers `501`, LR45a-7).
- **Console:** Settings → Encryption keys (hierarchy view, rekey,
  customer key import wizard with the wrapping key download); runner
  sandbox status on the Actions page.
- **Tests:** envelope v1/v2 round trips; rotation with previous keys;
  concurrent rewrap (one winner per row); missing-root refusal; BYOK import
  with a test-wrapped key (wrapping algorithm per K1); rekey progress and
  destroy; DELETE fallback; sandbox probes (Linux CI only, `//go:build
  linux`), including a test that a script cannot read another tenant's
  directory; prelude probe suite against both runners; retirement test;
  HSTS headers per listener; DSN warning table; stderr scrubber.

## 9. Decisions needed from the maintainer

1. **Per-tenant master keys (envelope v2):** confirm the hierarchy; it
   touches every sealed value (the rewrap is online and reversible only by
   keeping previous roots).
2. **Sandbox failure policy:** refuse to start (proposed) or warn when
   Landlock/seccomp are unavailable; opt-out variable name
   `ZEROAUTHY_RUNNER__UNSANDBOXED=1`.
3. **Database TLS default:** warn in 1.x (proposed), require in 2.0?
4. **External KMS** as root: later plan or never.

## 10. Local rulings and observation points

| ID | Ruling |
|---|---|
| LR45a-1 | Root kid = first 16 hex of SHA-256(key). |
| LR45a-2 | Refuse to start when a referenced root key is missing. |
| LR45a-3 | An imported customer root replaces the server root for that tenant. |
| LR45a-4 | Rekey deactivates then destroys the old TMK once unused. |
| LR45a-5 | Outbound policy enforced in the kernel where feasible. |
| LR45a-6 | HSTS only where zeroauthy terminates TLS, or by opt-in. |
| LR45a-7 | Plugins without `key_hierarchy.v1` stay on v1 envelopes. |

Observe later (`docs/superpowers/plan-1-followups.md`):

- **K1** Auth0's wrapping algorithm and imported key format.
- **K2** How Auth0 lists `tenant-encryption-key` entries.
- **K3** Concurrent pre-activation keys.
- **K4** Kernel-level address filtering without a seccomp notifier.
