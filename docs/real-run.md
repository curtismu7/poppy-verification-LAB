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

### Live result (2026-11-17, headless run against the same live Company and PingFederate)

The hand-run instance on 7822 (this repo at the merge commit, `MODE=real`, agent URL `https://local.ping-devops.com:7822`, TLS from the Company's own CA bundle) ran the whole suite with `signIn: true` and `scopes: { read: 'accounts:read', other: 'expense:read', escalate: 'admin:delete' }`:

**107 checks: 73 pass, 10 fail, 3 warn, 21 skip** — `conformant: false`, `complete: false`.

What the headless sign-in proved, with no browser and no person:

| Area | Result |
|---|---|
| The sign-in itself | pass: PAR push, the PF login form and the consent form were driven by the driver, the code came back with `iss`, the token request succeeded, and the signed call to `/poppy/api/v1/me` returned HTTP 200 (`a-signed-in`). |
| RFC 9207 | both pass: `iss` on the success redirect (`o-iss-success`) and on `access_denied` (`o-iss-error`, the driver's deny path answered the consent with deny). |
| PKCE | pass: a wrong verifier refused with `invalid_grant` (`o-pkce`); code replay refused (`o-code-replay`). |
| redirect_uri and resource binding on the token request | pass: `o-redirect-token`, `o-resource-token` both refused with the right error. |
| Scope enforcement on the API | pass: a token without the read scope got 403 `insufficient_scope` (`a-scope`). |

The 10 failures are real findings about the live stack, reported as the suite saw them (none has been tuned away):

- `o-scope-subset`, `o-scope-missing`, `o-scope-unknown`, `o-pkce-required`, `o-resource-unknown`: PingFederate refuses a bad PAR push with the right error **code** but through its own `invalid_request`/`invalid_scope`/`invalid_target` text, and the two consent-time checks (`o-scope-missing`) reached consent instead of being refused — the negative controls wanted the refusal at a specific step with a specific error. `o-scope-subset` also shows `granted undefined`: the token response carried no `scope` member for these grants, so the check cannot compare asked vs granted.
- `o-refresh`, `o-refresh-escalate`: the refresh grant is refused with `unauthorized_client` — the CIMD policy does not list `refresh_token` (or the token manager mapping rejects it), so the refresh checks cannot run meaningfully.
- `o-revoke`: revocation refused with `invalid_request` — the revocation endpoint rejected the request shape or the client.
- `o-assertion-aud-array`: an assertion with `aud` as a one-element array was accepted as far as the token step (`invalid_grant`, not `invalid_client`), so the aud-as-array refusal is not enforced (the SHOULD `o-assertion-lifetime` and `o-assertion-replay` warnings show the same shape: accepted, MAY-level).
- `a-mcp-default-token`: the probe origin answers 404 with no `WWW-Authenticate` challenge — the MCP resource is not at `/` on this Company, so the check's path assumption needs the Company's real MCP URL (the MCP sign-in checks skipped for the same reason: no access token manager matches that resource at PingFederate).

The 3 warnings: `s-delegation-cnf-private` (as in the first run) and MAY-level assertion lifetime/replay acceptance.

### Follow-up run after two issuer-side fixes (2026-11-17, container run)

Two of the findings were environment configuration, and both were fixed and re-run:

- **Refresh** (`o-refresh`, `o-refresh-escalate`): the refusal `unauthorized_client` came from the agent's own client document, which advertised `grant_types: ['authorization_code']` only. PingFederate honours the document for CIMD clients. Fixed in the lab (it now advertises `refresh_token` too — spec 4.4, the suite refreshes by design). Both refresh checks now pass: refresh works, an escalated refresh is refused with `invalid_scope`.
- **Revocation** (`o-revoke`, `o-revoke-other-client`): the token manager had `Enable Token Revocation` off. Switched on (one field, read back). Both revocation checks now pass — including the cross-client one: another client's revocation attempt is refused and the owner can still refresh. (Note: the earlier run's opposite finding — another client COULD revoke — was real with that config; the flag is the difference.)
- With the second agent identity (PR #8): `s-delegation-iss` and `a-token-client` pass; `o-refresh-other-client` still fails (the refused other-client refresh attempt consumes the owner's grant — `invalid_grant` on the owner's next refresh), reported as found.

**Result after the fixes: 79 pass, 12 fail, 3 warn, 13 skip.** The remaining fails are the four PAR error-shape/`scope`-member findings (PingFederate's own error text and consent-time refusals, plus no `scope` member in token responses), `o-assertion-aud-array` (an aud array is accepted as far as `invalid_grant`), and the MCP set. MCP stays an environment limit: this PingFederate has no MCP resource registered (the token manager lists no resource URIs, the Company's `poppy.json` publishes no MCP API), so those checks have nothing valid to point at.

### Third run: the suite's error-step and scope-omission strictness corrected (2026-11-17)

Two of the remaining "failures" were the suite being stricter than the standards, and both were fixed in the suite (the check, not the target):

- **`o-pkce-required`, `o-scope-unknown`, `o-resource-unknown`**: the checks wanted the refusal as an authorization redirect error; PingFederate refuses at the PAR endpoint instead. RFC 9126 §2.2 says a pushed request is validated and its error returned there — refusing at either step is conformant. The negative controls now accept the same error code at either step. All three pass, refused at the pushed step with the right code.
- **`o-scope-subset`**: PingFederate omits the `scope` member of the token response when it matches the request. RFC 6749 §5.1 allows exactly that (omission means "identical"). The check now treats an omitted scope as identical — and the driver translates a granted scope back into the suite's own names, so the comparison works in the issuer's scope space too. Passes, and the `grant_extra_scopes` defect still fails it (the Mock reference always includes the member).

**Result: 83 pass, 8 fail, 3 warn, 13 skip.**

The remaining non-MCP fails are genuine PingFederate behaviours that are not configuration-fixable, reported as findings:

- `o-scope-missing`: a sign-in with no scope parameter reaches consent instead of being refused with `invalid_scope` (spec 4.7).
- `o-assertion-aud-array`: a client assertion whose `aud` is a one-element array is accepted as far as `invalid_grant` (spec 4.1 wants one string; RFC 7523 permits arrays, so this is a SHOULD-level gap).
- `o-refresh-other-client`: when another client's refresh attempt is refused, the owner's grant is consumed too — the next owner refresh gets `invalid_grant`.

Skips (13): the 11 variant-client CIMD checks and the 2 PS384 checks.

