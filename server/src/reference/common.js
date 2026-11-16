// Shared pieces of the in-process reference Company and issuer. Everything here follows Personal Agent Protocol 1.0 as published
// 2026-11-14. A "defect" is a named, deliberate departure from that text; with none set the reference is the conformant behaviour
// and the verification suite is expected to pass. Defects exist so the suite can be shown to FAIL (a verifier that cannot fail proves nothing).
import crypto from 'node:crypto';

export const COMPANY_ORIGIN = 'https://company.example';
export const COMPANY_DOMAIN = 'company.example';
export const ISSUER = 'https://auth.company.example';
export const MCP_URL = 'https://company.example/mcp';
export const AGENT_ORIGIN = 'https://agent.example';
export const SPEC_VERSION = '1.0';

// Scope hints (spec 4.7): both fields in every entry; "changes" is none, reversible or irreversible.
export const SCOPES = {
  'orders:read': { description: 'See your orders and their status', changes: 'none', personal_data: true },
  'orders:write': { description: 'Place or change an order before it ships', changes: 'reversible', personal_data: true },
  'account:close': { description: 'Close your account for good', changes: 'irreversible', personal_data: true },
};

export const DEFECTS = {
  no_protected_resources: 'Issuer metadata omits protected_resources (spec 3.2 requires it)',
  no_revocation_endpoint: 'Issuer metadata omits revocation_endpoint (spec 3.2 requires it)',
  assertion_aud_token_endpoint: 'Accepts a client assertion whose aud is the token endpoint URL (spec 4.1: the issuer exactly)',
  assertion_long_lifetime: 'Accepts a client assertion that lasts more than 5 minutes (a Company MUST NOT reject up to 5; longer MAY be rejected, a long one is a smell)',
  grant_extra_scopes: 'Grants a scope that was not requested (spec 4.7: MUST NOT)',
  no_iss_param: 'Leaves iss (RFC 9207) off the authorization response (spec 4.2: every response, including errors)',
  iss_missing_on_error: 'Leaves iss off an error redirect such as access_denied (spec 4.2)',
  no_pkce: 'Does not require the PKCE code_verifier',
  loose_redirect_uri: 'Matches redirect_uri by prefix instead of exactly (spec 4.2)',
  follow_redirects: 'Follows a redirect when fetching client metadata (CIMD draft 5: MUST NOT)',
  jwks_other_host: 'Accepts a jwks_uri on another host than the client_id (spec 4.1: same domain)',
  no_version_check: 'Does not check Poppy-Version (spec 3.4: version_unsupported, HTTP 400)',
  session_401: 'Answers a bad Poppy-Session with 401 instead of 400 invalid_session (spec 5.3)',
  no_replay_check: 'Accepts a reused Session jti',
  no_aud_check: 'Does not check the Session aud against the Company identifier',
  no_htu_check: 'Does not bind the Session to the request URL (htu)',
  no_htm_check: 'Does not bind the Session to the request method (htm)',
  no_iat_window: 'Accepts a Session of any age',
  skip_ath: 'Does not check ath against the access token',
  accept_no_delegation: 'Accepts a Session signed directly with a jwks_uri key, with no delegation (spec 5.2: MUST reject)',
  long_delegation_ok: 'Accepts a delegation that lasts more than 24 hours (spec 5.2)',
  accept_any_typ: 'Does not check the typ of the Session or delegation JWT',
  accept_weak_alg: 'Accepts alg none or HS256 on a Session JWT',
  token_client_mismatch_ok: 'Accepts an access token issued to a different client than the Session iss (spec 5.3)',
  mcp_accepts_default_token: 'The MCP server accepts the default Company token (spec 4.5: only a token for its own resource)',
  no_audience_check: 'The API does not check the access token audience (spec 4.5)',
  scope_not_enforced: 'The API does not enforce the required scope',
  refresh_not_rotated_revoked_ok: 'A revoked refresh token still works',
};

export const nowSeconds = () => Math.floor(Date.now() / 1000);
export const rand = (n = 16) => crypto.randomBytes(n).toString('base64url');

export function jsonResponse(status, body, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers } });
}

/** A header lookup that works for a plain object, a Headers or a Map-like, case-insensitively. */
export function headerGetter(init) {
  const h = init?.headers;
  if (!h) return () => undefined;
  if (typeof h.get === 'function') return (k) => h.get(k) ?? undefined;
  const lower = Object.fromEntries(Object.entries(h).map(([k, v]) => [k.toLowerCase(), v]));
  return (k) => lower[k.toLowerCase()];
}

/** Hosts a Company must never be made to connect to for a URL the other party supplied (spec 3: loopback, private, link-local). */
export function isBlockedAddress(hostname) {
  const h = String(hostname).toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h.endsWith('.localhost') || h === '::1' || h === '::') return true;
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(h);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

export function formBody(text) { return Object.fromEntries(new URLSearchParams(String(text ?? ''))); }
