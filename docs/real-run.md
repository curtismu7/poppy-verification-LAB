# A Real run against a live Company and PingFederate (2026-11-17)

What this is: the Verify suite in Real mode against a live Company and issuer, from this machine. Anonymous discovery reads plus signed `Poppy-Session` probes with no access token. No sign-in happened and no credentials were used.

**Target:** a local demo Company (`https://company.example:3001` below) and a local PingFederate (`https://auth.company.example:9031` below) behind a metadata shim that adds `protected_resources`. Real hostnames are not shipped in this repo.

**How the agent was made reachable:** a second instance of this app ran with `MODE=real`, `PVL_AGENT_BASE_URL=https://agent.example:7822` (a name that resolves to this machine), a certificate the Company's CA bundle trusts and its own key. The Company's `POPPY_ALLOWED_AGENTS` gained that client URL. Nothing else about the Company changed.

## Result

107 checks: **50 pass, 0 fail, 2 warn, 55 skipped**, so `conformant` is true and `complete` is false (the skipped checks did not run). Two warnings: PingFederate does not advertise `authorization_response_iss_parameter_supported`, and the Company accepts a delegation whose `cnf.jwk` carries private key members (a recommendation, see below).

| | |
|---|---|
| Discovery (9 checks) | all pass: `organization.domain` carries the port, scope hints valid, protected resource metadata correct |
| Issuer metadata (12 checks) | all pass except one warning: PingFederate does not advertise `authorization_response_iss_parameter_supported` |
| Poppy-Session (30 checks run) | all pass: wrong audience, URL, method, stale or future time, wrong `typ`, alg none and HS256, no delegation, 48 hour delegation, expired delegation, unknown `kid`, forged and self-signed delegation, `ath` without a token, Poppy-Version missing or another major |
| Skipped (55) | 53 need a person to sign in; one needs a second agent identity; one needs PS384 (the real agent publishes an ES256 key only) |

**What changed the verdict:** the first run reported one failure (50 pass, 1 fail, 1 warn, 55 skipped), `s-delegation-cnf-private`: the Company accepted a delegation whose `cnf.jwk` carried private key members. Spec 5.2 puts the "MUST NOT" on the delegation the agent builds; its verification steps do not require a Company to refuse one. The check was stricter than the spec, so it is now a recommendation (a warning when accepted), and a mutation test pins that.

## Two fixes this run led to (already merged)

- The Company published `organization.domain` without its port (spec 1.0 section 3.1 wants the port when it is not 443). Fixed in the Company and in the older agent lab's check.
- The issuer metadata listed a different `protected_resources` than the Company's origin (spec 3.2): the shim's `SHIM_PROTECTED_RESOURCE` was corrected.

## Limits

One probe endpoint (`/poppy/api/v1/me`), signed out. Sign-in, refresh, revocation, PKCE, scope and MCP checks were not run against this Company; they need a person to sign in, which the Run it tab does.

## Two sign-in checks, run by hand through a browser (2026-11-17)

The suite cannot drive a real sign-in, so two of the 53 sign-in checks were run by following the Run it flow in Chrome: discover, push the request (PAR), sign in as the demo user on the PingFederate page, approve the consent, then make the signed call. PingFederate first needed a CIMD policy for this lab's client URL (created from the older lab's policy: same token manager, PKCE required). Before that policy, the push was refused with `invalid_client`.

| Check | Result | Evidence |
|---|---|---|
| `a-signed-in`: a signed-in call with a matching Session succeeds | **pass** | The Company answered HTTP 200 with `state: signed_in` and the scope `accounts:read`. The Session header was `poppy-session+jwt` / ES256 with `ath`, and its `sub` was the agent's own User ID, not the token's `sub`. The access token's `client_id` was this lab's client URL. |
| `o-iss-success`: the authorization response carries `iss` (RFC 9207) | **fail, then pass** | First, PingFederate's redirect carried a `code` and **no `iss`** (two sign-ins), and its metadata did not advertise `authorization_response_iss_parameter_supported`. Spec 4.2 asks for `iss` on every authorization response. PingFederate 13.1 has a setting for it, `includeIssuerInAuthorizationResponse`, which was off. After it was switched on (one field changed, read back), the metadata advertised the parameter and the redirect carried `iss` equal to the issuer, character for character. The lab records the redirect it receives (the `iss` value, whether a code or an error came back, never the code). |

**What changed because of it:**
- PingFederate: `includeIssuerInAuthorizationResponse` is now on. It adds `iss` to every authorization response of that server, for every client, which RFC 9207 clients handle.
- The agent: it now refuses a redirect with no `iss`, always (spec 4.2: it must check `iss` matches, which a missing one cannot do). Before, it only refused a wrong `iss`, or a missing one when the issuer said it always sends one. A test pins it: with a fake issuer that sends none and does not advertise the parameter, no token request is made.
- Result with both changes: a third sign-in succeeded, the signed call returned HTTP 200 again, and `o-iss-success` passes.

## Headless sign-in (no browser): the 51 sign-in checks against the live issuer

The Verify suite can now sign in to the issuer's login and consent pages by itself — an opt-in driver, on only when the server has `PVL_SIGNIN_USER` and `PVL_SIGNIN_PASSWORD` and the run asks for it (`signIn: true`). It handles the PingFederate HTML form adapter (login form, then the "Request for Approval" consent form with its `pf.oauth.authz.consent` hidden field) by parsing the pages, not scripting a browser. The credentials are read from the environment only, POSTed only to the typed issuer, and never appear in the report, the steps, the session log or an API response.

How it is tested in CI: the same in-process reference issuer that powers Mock mode is fronted by fake PingFederate-style pages, and every sign-in check must give the same verdict as under the Mock driver; variant-client checks (CIMD), PS384 and second-agent checks skip with their reasons, and three mutants of the driver itself (wrong verifier, dropped iss, fake token success) are caught by the suite.

Checks that still skip in Real mode, with the reason in the report:

- the CIMD variant-client checks (`o-cimd-*`, `o-redirect-exact`): the issuer would need a CIMD policy per variant URL, and the agent serves only its own document;
- `o-refresh-other-client`, `o-revoke-other-client`, `a-token-client`, `a-mcp-token-client`: they need a second agent identity;
- `s-ps384`, `o-assertion-ps384`: the real agent publishes an ES256 key only.

The scopes the checks use are mapped at run time (`scopes: { read, other, escalate }`), so no Company-specific scope name is baked into the repo.

*Live result with the 7822 hand-run instance: pending (run after merge; recorded here per the handoff).*
