# Setup for a Real run

Mock needs no setup. For Real you need three things: an issuer (PingFederate below), a Company, and this app reachable over https. This agent **refuses to sign in** unless the issuer metadata lists the Company under `protected_resources` (spec 3.2), lists a `revocation_endpoint`, and offers `refresh_token`.

1. **Company.** Any server that serves `/.well-known/poppy.json` (with `organization.domain` equal to its host and `protocol_version` 1.0, or any 1.x) and `/.well-known/oauth-protected-resource` (with `resource` equal to its origin), and an API that checks the bearer token and the `Poppy-Session` header. It must list this agent's `client.json` URL as an allowed agent.
2. **PingFederate.** Three objects, created through the admin API or console:
   - a **JWT access token manager** of its own, with its own signing key id, whose attribute contract includes `client_id` (and `sub`), with the `client_id` claim taken from the request's `ClientId` (a CONTEXT source) rather than a hardcoded value;
   - an **access token mapping** from your login adapter to that token manager that fulfils `client_id` from `CONTEXT / ClientId` and `sub` from the adapter's username;
   - a **CIMD policy** for the agent's client metadata URL (`${PVL_AGENT_BASE_URL}/client.json`) whose default token manager is the one above, with `restrictToDefaultAccessTokenManager` on and PKCE required.

   Traps: PingFederate allows one exact URL per CIMD policy; CIMD clients cannot use `pi.flow`; it caches CIMD clients for at least 5 minutes, so policy changes take that long to show; the policy's token manager only applies when the request has no `openid` scope; the client assertion header must be `client-authentication+jwt`; the consent form has a checked scope box that must stay checked or the token has no scope; a `resource` parameter (RFC 8707) is answered with HTTP 400 unless that resource URI is registered, so the tester sends it only when you tick the box.
3. **This app.** `PVL_AGENT_BASE_URL=https://agent.example PVL_AGENT_HOST=agent.example PVL_TLS_CERT=... PVL_TLS_KEY=... PVL_BIND=0.0.0.0 ./scripts/run.sh`. The URL must resolve to this machine from PingFederate and carry a certificate PingFederate trusts (set `NODE_EXTRA_CA_CERTS` for a local CA). The public name serves only `/client.json`, `/jwks.json` and the `/cb` sign-in redirect; the page and the API stay on loopback.

Then open the page on loopback, type the Company origin and the issuer, and go through the three steps.

## Headless sign-in for the Verify suite (optional)

By default the Verify suite's sign-in checks skip in Real mode: a person has to sign in. With two environment variables the suite can sign in by itself, with no browser, and run all 51 sign-in, token, refresh, revoke and MCP checks:

- `PVL_SIGNIN_USER` and `PVL_SIGNIN_PASSWORD` — a test user at the issuer, whose login page is an HTML form (a PingFederate HTML form adapter is what this was built against; any other page shape stops with `unsupported sign-in page: <title>` and the check skips). Set them on the SERVER process only: never in the browser, never in a request body, never a default. They are sent only to the issuer you typed, and they never appear in the report, the steps, the session log or an API response. In the compose file they are pass-through (`${PVL_SIGNIN_USER:-}`); do not bake values into it.
- On the Verify tab, tick **Sign in with the configured test user**, and fill the three scope fields, which map this suite's made-up scope names (`orders:read`, `orders:write`, `account:close`) onto what your Company actually uses: **read** (the scope the probe path needs), **other** (a scope that must NOT satisfy the probe path), **escalate** (one that is never granted). An unmapped scope makes that check skip rather than guess. `MCP resource URL` is optional and only needed if your Company serves an MCP endpoint.

Checks that need a variant client document (the CIMD refusals), a second agent identity, or a PS384 key skip in Real mode with the reason: the lab serves one agent identity, its own ES256 key and its own client document only.

## Scopes the Company advertises

The Company's authorization server is the shared PingFederate, and it advertises 55 scopes that belong to several demos. This tester asks only for `accounts:read` (the default when the Company offers it). The other 54 are not Poppy offerings. Narrowing the advertised set was considered and not done: PingFederate has no scope group or virtual-issuer setting that hides scopes from its metadata, and other demos read the same metadata. The decision (2026-10-30, owner) is to keep PingFederate and document the shared set.

## Issuer in the authorization response (RFC 9207, spec 4.2)

The agent refuses a sign-in redirect that carries no `iss`, or an `iss` that is not the issuer it started with. PingFederate sends `iss` only when **Authorization Server Settings, "Include issuer in authorization response"** is on (admin API: `oauth/authServerSettings`, field `includeIssuerInAuthorizationResponse`; checked on 13.1.3, where it was off). With it off, the redirect has a `code` and no `iss`, and this lab shows `iss_mismatch` with `redirect iss missing`. With it on, the issuer metadata also advertises `authorization_response_iss_parameter_supported: true`.

## The protected_resources field

Spec 3.2 requires the issuer's metadata (RFC 8414) to list `https://{company domain}` under `protected_resources`, with no path or trailing slash, and an agent must check it. PingFederate publishes no such field (no setting found; the 13.1 documentation index shows none, which is not conclusive). Put a small metadata layer in front of the issuer that adds it, keeping the issuer string unchanged, or ask for the setting. Until then a bare PingFederate fails the Run it discovery by design, and the Verify tab's `as-protected-resources` check shows why.
