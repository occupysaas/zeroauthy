# Black-box clients

zeroauthy is tested with Auth0's own open-source SDKs and libraries, chosen in
order of GitHub stars (github.com/orgs/auth0/repositories?q=sort:stars), as
the maintainer asked on 2026-10-16. Versions are pinned in tests/e2e/package.json.

| Repository | Stars (2026-10-16) | Used in | Surfaces |
|---|---|---|---|
| node-jsonwebtoken | 18k | m10 (through express-jwt) | access token verification |
| express-jwt | 4.5k | m10 | access token verification with JWKS |
| nextjs-auth0 | 2.3k | m5 | login, session, refresh, logout |
| auth0-spa-js | 1.0k | m4, m6, m10 | PKCE login, silent auth, confirmation |
| auth0-react | 991 | m5 | refresh rotation, logout |
| node-jwks-rsa | 876 | m10 | JWKS |
| node-auth0 | 682 | m3, m6, m9, m10 | password grants, dbconnections, access policy |
| express-openid-connect | 519 | m10 | third-party consent (web app) |
| express-oauth2-jwt-bearer | — | m3, m4 | access token verification |
| auth0-auth-js | — | m6, m9 | password grant, dbconnections |

## Not yet used (in star order), with the milestone that should pick them up

| Repository | Stars | Planned for |
|---|---|---|
| java-jwt | 6.2k | OIDF/JWT interop job (milestone 11) |
| jwt-decode | 3.4k | milestone 11 (decode ID tokens in a browser test) |
| angular2-jwt / auth0-angular | 2.6k / 201 | milestone 11 (Angular SPA) |
| go-jwt-middleware | 1.2k | milestone 11 (Go resource server) |
| lock / auth0.js | 1.1k / 1.1k | not planned: embedded/classic login (deprecated by Auth0 in favour of Universal Login); revisit if requested |
| auth0-python | 578 | milestone 11 (Authentication API client) |
| react-native-auth0, Auth0.swift, Auth0.Android | 551 / 465 / 301 | device flow plan (Plan 11) or later: native redirect handling |
| auth0-PHP, auth0.net, auth0-java, ruby-auth0, laravel-auth0 | 410 … 205 | milestone 11 (one per language as an Authentication API client) |
| auth0-cli, auth0-deploy-cli, terraform-provider-auth0, go-auth0 | 343 / 282 / 222 / 197 | sub-project 3 (Management API) |
| passport-auth0 | 305 | milestone 11 |
