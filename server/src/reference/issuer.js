// The reference authorization server: Personal Agent Protocol 1.0 section 3.2 (metadata) and section 4 (OAuth). It is mock-issued:
// every token it makes is labelled by the page as mock. In-memory, one process, nothing persisted.
import crypto from 'node:crypto';
import { generateEs256Key, signJwsAlg, parseJws, verifyJws, thumbprint } from '../jose.js';
import { makeClientResolver } from './clientResolver.js';
import { COMPANY_ORIGIN, COMPANY_DOMAIN, ISSUER, MCP_URL, SCOPES, jsonResponse, formBody, headerGetter, isBlockedAddress, rand, nowSeconds } from './common.js';

export class OAuthError extends Error {
  constructor(error, description, status = 400) { super(description || error); this.error = error; this.description = description; this.status = status; }
}

const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const KNOWN_RESOURCES = new Set([COMPANY_ORIGIN, MCP_URL]);

export function createIssuer({ defects = new Set(), now = nowSeconds, fetchImpl, parRequired = false } = {}) {
  const key = generateEs256Key();
  const kid = thumbprint(key.publicJwk);
  const codes = new Map(); // code -> { client, redirectUri, challenge, scopes, resource, expires }
  const parStore = new Map(); // request_uri -> { params, client_id, expires }
  const pendingAuth = new Map(); // id -> authorization request waiting for consent
  const refresh = new Map(); // token -> { clientId, scopes, account, revoked }
  const seenJti = new Map(); // client assertion jti -> expiry
  const has = (d) => defects.has(d);

  const metadata = () => {
    const m = {
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      pushed_authorization_request_endpoint: `${ISSUER}/par`,
      require_pushed_authorization_requests: parRequired,
      jwks_uri: `${ISSUER}/jwks.json`,
      grant_types_supported: ['authorization_code', 'refresh_token'],
      response_types_supported: ['code'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['private_key_jwt'],
      token_endpoint_auth_signing_alg_values_supported: ['ES256', 'PS384'],
      authorization_response_iss_parameter_supported: true,
      scopes_supported: Object.keys(SCOPES),
      protected_resources: [COMPANY_ORIGIN, MCP_URL],
      revocation_endpoint: `${ISSUER}/revoke`,
    };
    if (has('no_protected_resources')) delete m.protected_resources;
    if (has('no_revocation_endpoint')) delete m.revocation_endpoint;
    return m;
  };

  const resolveClient = makeClientResolver({ fetchImpl, has, OAuthError });

  // private_key_jwt (spec 4.1, RFC 7523 with the 7523bis audience): signed by a key in the client's jwks_uri.
  async function authenticateClient(form) {
    if (form.client_assertion_type !== ASSERTION_TYPE || !form.client_assertion) throw new OAuthError('invalid_client', 'a private_key_jwt client assertion is required', 401);
    const a = parseJws(form.client_assertion);
    if (!a) throw new OAuthError('invalid_client', 'the client assertion is not a JWT', 401);
    const clientId = a.payload.iss;
    if (a.payload.sub !== clientId || (form.client_id && form.client_id !== clientId)) throw new OAuthError('invalid_client', 'assertion iss and sub must both be the client_id', 401);
    const client = await resolveClient(clientId);
    const candidates = a.header.kid ? client.keys.filter((k) => k.kid === a.header.kid) : (client.keys.length === 1 ? client.keys : []);
    if (!candidates.some((k) => verifyJws(a, k))) throw new OAuthError('invalid_client', 'the assertion signature does not verify with a key published at jwks_uri (alg must be ES256 or PS384)', 401);
    const t = now();
    const audOk = a.payload.aud === ISSUER || (has('assertion_aud_token_endpoint') && a.payload.aud === `${ISSUER}/token`);
    if (!audOk) throw new OAuthError('invalid_client', `assertion aud must be the issuer ${ISSUER} as one string (the token endpoint URL is refused)`, 401);
    if (!Number.isFinite(a.payload.iat) || !Number.isFinite(a.payload.exp)) throw new OAuthError('invalid_client', 'assertion needs iat and exp', 401);
    if (a.payload.exp <= t - 60 || a.payload.iat > t + 60) throw new OAuthError('invalid_client', 'assertion is expired or from the future', 401);
    if (a.payload.exp - a.payload.iat > 300 && !has('assertion_long_lifetime')) throw new OAuthError('invalid_client', 'assertion lifetime exceeds 5 minutes', 401);
    if (typeof a.payload.jti !== 'string' || a.payload.jti.length < 8) throw new OAuthError('invalid_client', 'assertion needs a unique jti', 401);
    for (const [j, e] of seenJti) if (e < t) seenJti.delete(j);
    if (seenJti.has(a.payload.jti)) throw new OAuthError('invalid_client', 'assertion jti was already used', 401);
    seenJti.set(a.payload.jti, a.payload.exp);
    return client;
  }

  const redirectMatches = (client, uri) => (client.meta.redirect_uris ?? []).some((r) => (has('loose_redirect_uri') ? uri.startsWith(r) : r === uri || (new URL(r).hostname === '127.0.0.1' && new URL(uri).hostname === '127.0.0.1' && r.split(':').slice(0, 2).join(':') === uri.split(':').slice(0, 2).join(':') && new URL(r).pathname === new URL(uri).pathname)));

  /** Pushed authorization request (RFC 9126): the agent authenticates and parks its parameters. */
  async function par(form) {
    const client = await authenticateClient(form);
    const params = Object.fromEntries(Object.entries(form).filter(([k]) => !['client_assertion', 'client_assertion_type'].includes(k)));
    if (params.request_uri) throw new OAuthError('invalid_request', 'request_uri is not allowed in a pushed request');
    const request_uri = `urn:ietf:params:oauth:request_uri:${rand(18)}`;
    parStore.set(request_uri, { params: { ...params, client_id: client.clientId }, expires: now() + 60 });
    return { request_uri, expires_in: 60 };
  }

  const redirectWith = (base, q, { withIss = true, isError = false } = {}) => {
    const u = new URL(base);
    for (const [k, v] of Object.entries(q)) if (v !== undefined) u.searchParams.set(k, v);
    const skipIss = has('no_iss_param') || (isError && has('iss_missing_on_error'));
    if (withIss && !skipIss) u.searchParams.set('iss', ISSUER);
    return u.href;
  };

  /**
   * Direct Sign-In (spec 4.2): validate the request. Returns { kind: 'error' } (not safe to redirect), { kind: 'redirect', url } (an
   * error that goes back to the agent, always with iss) or { kind: 'consent', id, ... } for the page to show.
   */
  async function startAuthorization(query) {
    let p = { ...query };
    try {
      if (p.request_uri) {
        const hit = parStore.get(p.request_uri);
        parStore.delete(p.request_uri);
        if (!hit || hit.expires < now() || hit.params.client_id !== p.client_id) throw new OAuthError('invalid_request', 'unknown or expired request_uri');
        p = { ...hit.params, client_id: hit.params.client_id };
      } else if (parRequired) throw new OAuthError('invalid_request', 'this issuer requires pushed authorization requests (RFC 9126): push first, then open authorize with only client_id and request_uri');
      const client = await resolveClient(p.client_id);
      if (!p.redirect_uri || !redirectMatches(client, p.redirect_uri)) return { kind: 'error', error: 'invalid_request', description: 'redirect_uri must exactly match one of the redirect_uris in the client metadata' };
      const back = (error, description) => ({ kind: 'redirect', url: redirectWith(p.redirect_uri, { error, error_description: description, state: p.state }, { isError: true }) });
      if (p.response_type !== 'code') return back('unsupported_response_type', 'only response_type=code');
      if (!has('no_pkce') && (!p.code_challenge || p.code_challenge_method !== 'S256')) return back('invalid_request', 'PKCE with S256 is required');
      const scopes = String(p.scope ?? '').split(' ').filter(Boolean);
      if (!scopes.length) return back('invalid_scope', 'scope is required on every sign-in');
      if (scopes.some((s) => !SCOPES[s])) return back('invalid_scope', 'a requested scope is unknown');
      if (p.resource && !KNOWN_RESOURCES.has(p.resource)) return back('invalid_target', 'unknown resource');
      const id = rand(16);
      pendingAuth.set(id, { id, client, params: p, scopes, expires: now() + 600 });
      if (pendingAuth.size > 200) pendingAuth.delete(pendingAuth.keys().next().value);
      // prompt=consent is honoured by always showing the consent page, even when every scope was granted before.
      return { kind: 'consent', id, clientName: client.meta.client_name ?? client.clientId, clientId: client.clientId, company: COMPANY_DOMAIN, scopes: scopes.map((s) => ({ name: s, ...SCOPES[s] })) };
    } catch (e) {
      if (e instanceof OAuthError) return { kind: 'error', error: e.error, description: e.description };
      throw e;
    }
  }

  /** What the consent screen shows for a waiting request (spec 4.2: the Company, the account, the scopes, the consequences). */
  function pending(id) {
    const a = pendingAuth.get(id);
    if (!a || a.expires < now()) return null;
    return { id, clientName: a.client.meta.client_name ?? a.client.clientId, clientId: a.client.clientId, company: COMPANY_DOMAIN, scopes: a.scopes.map((s) => ({ name: s, ...SCOPES[s] })), resource: a.params.resource ?? null };
  }

  function approve(id, grant = null) {
    const a = pendingAuth.get(id);
    pendingAuth.delete(id);
    if (!a || a.expires < now()) throw new OAuthError('invalid_request', 'this sign-in expired; start again');
    let scopes = grant ? a.scopes.filter((s) => grant.includes(s)) : a.scopes;
    if (!scopes.length) return { url: redirectWith(a.params.redirect_uri, { error: 'access_denied', error_description: 'the user approved nothing', state: a.params.state }, { isError: true }) };
    if (has('grant_extra_scopes')) scopes = [...scopes, 'account:close'];
    const code = rand(24);
    codes.set(code, { client: a.client, redirectUri: a.params.redirect_uri, challenge: a.params.code_challenge, scopes, resource: a.params.resource, expires: now() + 60 });
    return { url: redirectWith(a.params.redirect_uri, { code, state: a.params.state }), scopes };
  }

  function deny(id) {
    const a = pendingAuth.get(id);
    pendingAuth.delete(id);
    if (!a) throw new OAuthError('invalid_request', 'this sign-in expired');
    return { url: redirectWith(a.params.redirect_uri, { error: 'access_denied', error_description: 'the user declined', state: a.params.state }, { isError: true }) };
  }

  const mintAccess = ({ clientId, scopes, resource }) => {
    const t = now();
    const aud = resource || COMPANY_ORIGIN;
    const payload = { iss: ISSUER, sub: 'acct-1001', aud, client_id: clientId, scope: scopes.join(' '), iat: t, exp: t + 3600, jti: rand(12) };
    return { token: signJwsAlg('ES256', { typ: 'at+jwt', kid }, payload, key.privateKey), payload };
  };
  const tokenResponse = ({ clientId, scopes, resource, account = 'acct-1001', refreshToken }) => {
    const at = mintAccess({ clientId, scopes, resource });
    return { access_token: at.token, token_type: 'Bearer', expires_in: 3600, refresh_token: refreshToken, scope: scopes.join(' ') };
  };

  async function token(form) {
    const client = await authenticateClient(form);
    if (form.resource && !KNOWN_RESOURCES.has(form.resource)) throw new OAuthError('invalid_target', 'unknown resource');
    if (form.grant_type === 'authorization_code') {
      const c = codes.get(form.code);
      codes.delete(form.code);
      if (!c || c.expires < now() || c.client.clientId !== client.clientId) throw new OAuthError('invalid_grant', 'the code is unknown, expired, used or for another client');
      if (c.redirectUri !== form.redirect_uri) throw new OAuthError('invalid_grant', 'redirect_uri differs from the authorization request');
      if (!has('no_pkce')) {
        const chal = form.code_verifier ? crypto.createHash('sha256').update(form.code_verifier).digest('base64url') : null;
        if (!chal || chal !== c.challenge) throw new OAuthError('invalid_grant', 'PKCE verification failed');
      }
      const rt = `rt_${rand(24)}`;
      refresh.set(rt, { clientId: client.clientId, scopes: c.scopes, revoked: false });
      return tokenResponse({ clientId: client.clientId, scopes: c.scopes, resource: form.resource, refreshToken: rt });
    }
    if (form.grant_type === 'refresh_token') {
      const r = refresh.get(form.refresh_token);
      if (!r || r.clientId !== client.clientId || (r.revoked && !has('refresh_not_rotated_revoked_ok'))) throw new OAuthError('invalid_grant', 'the refresh token is unknown, replaced, revoked or for another client');
      let scopes = r.scopes;
      if (form.scope) {
        const asked = form.scope.split(' ').filter(Boolean);
        if (asked.some((s) => !r.scopes.includes(s))) throw new OAuthError('invalid_scope', 'a refresh may ask for fewer scopes, never more');
        scopes = asked;
      }
      r.revoked = true; // rotation (RFC 6749 section 6): the old token is replaced, so reuse of it fails
      const rt = `rt_${rand(24)}`;
      refresh.set(rt, { clientId: client.clientId, scopes: r.scopes, revoked: false });
      return tokenResponse({ clientId: client.clientId, scopes, resource: form.resource, refreshToken: rt });
    }
    throw new OAuthError('unsupported_grant_type', 'this issuer offers authorization_code and refresh_token');
  }

  async function revoke(form) {
    const client = await authenticateClient(form);
    const r = refresh.get(form.token);
    if (r && r.clientId === client.clientId) r.revoked = true; // RFC 7009: success whether or not the token was known
    return {};
  }

  const verifyAccessToken = (token) => {
    const p = parseJws(token);
    if (!p || p.header.alg !== 'ES256' || !verifyJws(p, key.publicJwk)) return null;
    if (p.payload.iss !== ISSUER || !(p.payload.exp > now())) return null;
    return p.payload;
  };

  // The in-process "network" for the issuer host. The authorize endpoint is a browser page, served by the app, not here.
  async function handle(url, init = {}) {
    const u = new URL(url);
    const method = String(init.method || 'GET').toUpperCase();
    try {
      if (method === 'GET' && u.pathname === '/.well-known/oauth-authorization-server') return jsonResponse(200, metadata());
      if (method === 'GET' && u.pathname === '/jwks.json') return jsonResponse(200, { keys: [{ ...key.publicJwk, kid, alg: 'ES256', use: 'sig' }] });
      if (method === 'POST' && ['/par', '/token', '/revoke'].includes(u.pathname)) {
        const ct = String(headerGetter(init)('content-type') || '');
        if (!ct.startsWith('application/x-www-form-urlencoded')) throw new OAuthError('invalid_request', 'send application/x-www-form-urlencoded');
        const form = formBody(init.body);
        const out = u.pathname === '/par' ? await par(form) : u.pathname === '/token' ? await token(form) : await revoke(form);
        return jsonResponse(u.pathname === '/par' ? 201 : 200, out);
      }
      return jsonResponse(404, { error: 'not_found' });
    } catch (e) {
      if (e instanceof OAuthError) return jsonResponse(e.status, { error: e.error, error_description: e.description });
      throw e;
    }
  }

  return { metadata, handle, startAuthorization, pending, approve, deny, verifyAccessToken, publicJwk: key.publicJwk, kid, countRefreshTokens: () => refresh.size };
}
