This fixture runs entirely offline. `build.mjs OUTPUT` packages the installed
`tests/e2e/node_modules/auth0@7.4.0` and its complete dependency closure into
tarballs, checking each package version against `tests/e2e/package-lock.json`.
It preserves the real SDK's CommonJS and ESM exports; it does not replace the
SDK with a stub or run package lifecycle scripts.

`serve.mjs OUTPUT` serves only that metadata and those tarballs on loopback
port 9187. Unknown packages return 404 locally. The Actions build manager uses
this registry and a fresh private cache, so the acceptance lane cannot obtain
dependencies from the public npm registry. It requires the pinned dependencies
to be installed before running; it performs no install/download itself.

The closure currently contains `auth0` 7.4.0 and its alias `auth0` 4.37.1,
`uuid` 11.1.1, `jose` 5.10.0 and 4.15.9, and `undici-types` 6.29.0.
