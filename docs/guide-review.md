# Review of the Relying Party Implementation Guide, and where this lab answers each point

Reviewed 2026-11-16 against the Personal Agent Protocol 1.0 specification (published 2026-11-14) and the Ping documentation the guide cites. The guide is not part of this repo; this file records what needs changing in it and which Verify check or code proves the point. "Spec 5.3" means the 1.0 specification, section 5.3.

## Must fix in the guide

| # | Guide says | Spec or docs say | Evidence in this lab |
|---|---|---|---|
| 1 | Status checked 2026-11-13, "per your confirmation" 1.0 is final, website may show an outdated label | The changelog says 1.0 was published 2026-11-14. The word "final" is not used. No outdated label found | README, UI copy say "published 2026-11-14" |
| 2 | The issuer must be among the authorization servers the protected resource lists | That is half of the link. The issuer metadata must also list the Company under `protected_resources` (spec 3.2) | check `as-protected-resources`; defect `no_protected_resources`; the agent refuses to sign in without it |
| 3 | Do not advertise Device Sign-In in `poppy.json` | It is advertised in the issuer metadata: `grant_types_supported` plus `device_authorization_endpoint` (spec 3.2, 4.3) | check `as-device` |
| 4 | Session JWT validation is described loosely | Session `typ` poppy-session+jwt, alg ES256 only; delegation `typ` poppy-delegation+jwt, ES256 or PS384, at most 24 h, `cnf.jwk`; `poppy_dlg` is a JWT header parameter, not an HTTP header; `aud` is the Company identifier; no `exp`; `ath` absent without a token; token `client_id` equals Session `iss` (spec 5.2, 5.3) | checks `s-typ-session`, `s-alg-none`, `s-alg-hs256`, `s-no-delegation`, `s-delegation-24h`, `s-delegation-typ`, `s-delegation-rogue`, `s-ath-no-token`, `a-token-client`, `s-ps384` |
| 5 | `Poppy-Version` is not mentioned | Every Session endpoint must reject a missing or incompatible version with `version_unsupported`, HTTP 400 (spec 3.4) | checks `s-version-missing`, `s-version-major`; defect `no_version_check` |
| 6 | No error semantics | Session failures are HTTP 400 with `invalid_session`, `session_ended` or `version_unsupported`, not 401 (spec 5.3, 7) | check `s-status-400`; defect `session_401` |
| 7 | Assertion audience "enforced" | `aud` must be the issuer as one string; the token endpoint URL is refused; `exp` at most 5 minutes after `iat`; ES256 and PS384 must both be accepted; `private_key_jwt` is required (spec 4.1) | checks `o-assertion-aud`, `o-assertion-lifetime`, `o-assertion-replay`, `o-assertion-ps384` |
| 8 | CIMD fetch: "restrict redirect URIs" | The fetch must not follow redirects; `client_id` equals the fetched URL; `jwks_uri` and redirect URIs on the same domain (loopback allowed for redirects); no loopback, private or link-local targets (spec 3, 4.1) | checks `o-cimd-redirect`, `o-cimd-jwks-host`, `o-cimd-mismatch`, `o-cimd-loopback` |
| 9 | Scopes "minimum" | A Company must not grant scopes beyond those requested; `iss` (RFC 9207) on every authorization response including errors; `prompt=consent` supported; exact `redirect_uri`; PAR when `require_pushed_authorization_requests` is true (spec 4.2, 4.7) | checks `o-scope-subset`, `o-iss-success`, `o-iss-error`, `o-redirect-exact`, `o-pkce`, `as-par` |
| 10 | Roadmap list | Also lists delegated sign-in; Mediated Sign-In removal is dated 2027-03-17; the roadmap sits on the Introduction page | not a code point |
| 11 | Browser join is only gestured at | A code and cookie handshake, a required `poppy:browser-sign-in` scope for a signed-in join, and `web.unscoped` (spec 6) | **not covered by this lab** |
| 12 | PingOne MT is a "best fit" issuer | Our tests found no CIMD client type and no `protected_resources`; PAR works; assertions expect the token endpoint audience (gaps P1-1 to P1-3 in the parent repo's notes) | stated in the Run it gaps box |
| 13 | Section 7 PingFederate row: "for PingOne Neo use the wallet-based interaction method instead" | The sentence does not parse | editorial |

## Worth adding to the guide

- PingFederate caches CIMD documents about 5 minutes with no eviction, so a revoked agent stays accepted for that long (parent repo gap PF-3).
- The consent page can list every scope the issuer advertises, and a checked scope box must stay checked or the token has no scope (gap PF-6). The reference issuer here lists only the requested scopes.
- The agent assigns the User ID (spec 5.1: opaque, per Company, never derived from personal information). The parent lab used the token `sub`; this fork does not (test `the Session names the User ID this agent assigned`).
- The conversation channel (spec 8) and the tasks endpoint (spec 9) are missing from the guide's patterns. This lab does not cover them either.

## Ping claims checked against the documentation

| Claim | Result |
|---|---|
| AIC CIMD profile path, SSRF setting, metadata override denylist, no redirects, no CIBA for CIMD clients | verified |
| AIC CIBA nodes, grant, `acr_values` mapping, transactional warning | verified |
| PingFederate 13.1 CIBA | verified |
| PingFederate 13.1 CIMD | documented; lists PAR, refresh, device_code, token-exchange; no CIBA |
| PingGateway 2026 MCP security gateway | exists; interface marked "Evolving" |
| PingOne Authorize PRM and external token source | verified: you host the PRM; built-in rules are not available for external tokens |
| PingOne applications: Private Key JWT, device grant, PAR | verified |
| PingOne Recognize is single-factor; the Neo wallet pattern | **not confirmed**: no documentation page found for either |
| PingFederate emitting `protected_resources` | inconclusive: not found, but the documentation index was not read in full |

## Limits of this review

Spec sections 10.7, 10.8 and 11 were read as summaries, and the Operations extension was not read. Both are open.
