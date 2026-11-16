// The reference Company (relying party): poppy.json, protected resource metadata, an API and an MCP endpoint that verify the
// Poppy-Session header exactly as Personal Agent Protocol 1.0 section 5 asks. A Session identifies activity; it grants nothing.
// Authorization (token, audience, scope) is decided separately below.
import { parseJws, verifyJws, thumbprint } from '../jose.js';
import crypto from 'node:crypto';
import { makeClientResolver } from './clientResolver.js';
import { OAuthError } from './issuer.js';
import { COMPANY_ORIGIN, COMPANY_DOMAIN, ISSUER, MCP_URL, SCOPES, SPEC_VERSION, jsonResponse, headerGetter, nowSeconds } from './common.js';

const SESSION_TYP = 'poppy-session+jwt';
const DELEGATION_TYP = 'poppy-delegation+jwt';
const IAT_WINDOW = 60; // seconds, "such as one minute" (spec 5.3); the guides suggest 30s of clock skew inside it
const MAX_DELEGATION = 24 * 3600;
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'];

class SessionError extends Error {}
const bad = (m) => new SessionError(m);

export function createCompany({ defects = new Set(), now = nowSeconds, issuer, fetchImpl } = {}) {
  const has = (d) => defects.has(d);
  const resolveClient = makeClientResolver({ fetchImpl, has, OAuthError });
  const replay = new Map(); // `${iss}|${jti}` -> expiry
  const keyBinding = new Map(); // delegated key thumbprint -> sub (one User ID per delegated key)
  const sessionBinding = new Map(); // `${iss}|${sid}` -> sub

  const poppyJson = () => ({
    protocol_version: SPEC_VERSION,
    organization: { name: 'Example Outfitters', domain: COMPANY_DOMAIN },
    auth: {
      issuer: ISSUER,
      scopes: Object.fromEntries(Object.entries(SCOPES).map(([k, v]) => [k, v.description])),
      scope_hints: Object.fromEntries(Object.entries(SCOPES).map(([k, v]) => [k, { changes: v.changes, personal_data: v.personal_data }])),
    },
    apis: [
      { type: 'openapi', url: `${COMPANY_ORIGIN}/openapi.json`, description: 'Orders and catalog' },
      { type: 'mcp', url: MCP_URL, description: 'The same orders, as MCP tools' },
    ],
  });
  const protectedResource = () => ({ resource: COMPANY_ORIGIN, authorization_servers: [ISSUER], scopes_supported: Object.keys(SCOPES) });
  const mcpResource = () => ({ resource: MCP_URL, authorization_servers: [ISSUER], scopes_supported: ['orders:read'] });
  const openapi = () => ({
    openapi: '3.1.0', info: { title: 'Example Outfitters', version: '1' },
    paths: { '/poppy/api/v1/catalog': { get: { summary: 'Public catalog (a Session, no sign-in)', responses: { 200: { description: 'ok' } } } }, '/poppy/api/v1/me': { get: { summary: 'Your account', security: [{ oauth: ['orders:read'] }], responses: { 200: { description: 'ok' } } } } },
    components: { securitySchemes: { oauth: { type: 'oauth2', flows: { authorizationCode: { authorizationUrl: `${ISSUER}/authorize`, tokenUrl: `${ISSUER}/token`, scopes: Object.fromEntries(Object.entries(SCOPES).map(([k, v]) => [k, v.description])) } } } } },
  });

  /** Spec 5.3: verify the Poppy-Session header. Throws SessionError; returns the verified identity. */
  async function verifySession({ header, method, url, accessToken }) {
    const s = parseJws(header);
    if (!s) throw bad('Poppy-Session is not a JWT');
    if (!has('accept_weak_alg') && s.header.alg !== 'ES256') throw bad('Poppy-Session alg must be ES256');
    if (has('accept_weak_alg') && !['ES256', 'none', 'HS256'].includes(s.header.alg)) throw bad('Poppy-Session alg');
    if (!has('accept_any_typ') && s.header.typ !== SESSION_TYP) throw bad(`Poppy-Session typ must be ${SESSION_TYP}`);
    const t = now();

    // The delegation: a jwks_uri key vouches for a short-lived delegated key (spec 5.2).
    let delegatedJwk;
    let clientId;
    let delegationExp = Infinity;
    if (typeof s.header.poppy_dlg !== 'string') {
      if (!has('accept_no_delegation')) throw bad('a Session without a delegation is refused, including one signed directly with a jwks_uri key');
      clientId = s.payload.iss;
      const client = await resolveClient(clientId).catch((e) => { throw bad(e.message); });
      if (!client.keys.some((k) => verifyJws(s, k))) throw bad('Poppy-Session signature does not verify');
    } else {
      const d = parseJws(s.header.poppy_dlg);
      if (!d) throw bad('the delegation is not a JWT');
      if (!has('accept_any_typ') && d.header.typ !== DELEGATION_TYP) throw bad(`delegation typ must be ${DELEGATION_TYP}`);
      if (typeof d.payload.iss !== 'string' || typeof d.header.kid !== 'string' || typeof d.payload.jti !== 'string') throw bad('the delegation needs iss, kid and jti');
      const jwk = d.payload.cnf?.jwk;
      if (!jwk || typeof jwk !== 'object' || PRIVATE_MEMBERS.some((m) => m in jwk)) throw bad('cnf.jwk is missing or holds private key members');
      if (!Number.isFinite(d.payload.iat) || !Number.isFinite(d.payload.exp)) throw bad('the delegation needs iat and exp');
      if (d.payload.exp - d.payload.iat > MAX_DELEGATION && !has('long_delegation_ok')) throw bad('the delegation lasts more than 24 hours');
      if (d.payload.exp < t) throw bad('the delegation has expired');
      if (['sub', 'agent_id', 'aud'].some((k) => k in d.payload)) throw bad('a delegation must not carry a User ID, Agent ID or Company');
      clientId = d.payload.iss;
      const client = await resolveClient(clientId).catch((e) => { throw bad(e.message); });
      const signer = client.keys.find((k) => k.kid === d.header.kid);
      if (!signer || !verifyJws(d, signer)) throw bad('the delegation is not signed by a key published at the client jwks_uri');
      if (s.header.kid !== thumbprint(jwk)) throw bad('Poppy-Session kid is not the delegated key thumbprint');
      if (!(has('accept_weak_alg') && ['none', 'HS256'].includes(s.header.alg)) && !verifyJws(s, jwk)) throw bad('Poppy-Session signature does not verify with the delegated key');
      delegatedJwk = jwk;
      delegationExp = d.payload.exp;
      if (d.payload.iss !== s.payload.iss) throw bad('Poppy-Session iss must equal the delegation iss');
    }

    const c = s.payload;
    if (!has('no_aud_check') && c.aud !== ISSUER) throw bad(`Poppy-Session aud must be the Company identifier ${ISSUER}, character for character`);
    if (typeof c.sid !== 'string' || c.sid.length < 16 || typeof c.sub !== 'string' || typeof c.jti !== 'string' || typeof c.iss !== 'string') throw bad('Poppy-Session needs iss, sid (unguessable), sub and jti');
    if (!has('no_htm_check') && c.htm !== method.toUpperCase()) throw bad('htm does not match the request method');
    const htu = url.split('#')[0].split('?')[0];
    if (!has('no_htu_check') && c.htu !== htu) throw bad('htu does not match the request URL');
    if (!has('no_iat_window') && (!Number.isFinite(c.iat) || Math.abs(t - c.iat) > IAT_WINDOW)) throw bad('iat is outside the accepted window');
    if (c.iat > delegationExp) throw bad('the Session was signed after the delegation expired');
    if (!accessToken && c.ath !== undefined) throw bad('ath must be absent when the request has no access token');
    if (accessToken && !has('skip_ath')) {
      const ath = crypto.createHash('sha256').update(accessToken).digest('base64url');
      if (c.ath !== ath) throw bad('ath does not match the access token');
    }
    if (!has('no_replay_check')) {
      for (const [j, e] of replay) if (e < t) replay.delete(j);
      if (replay.has(`${c.iss}|${c.jti}`)) throw bad('this Session jti was already used');
      replay.set(`${c.iss}|${c.jti}`, t + 2 * IAT_WINDOW);
    }
    const sidKey = `${c.iss}|${c.sid}`;
    if (sessionBinding.has(sidKey) && sessionBinding.get(sidKey) !== c.sub) throw bad('this sid already belongs to another User ID');
    sessionBinding.set(sidKey, c.sub);
    if (delegatedJwk) {
      const tp = thumbprint(delegatedJwk);
      if (keyBinding.has(tp) && keyBinding.get(tp) !== c.sub) throw bad('this delegated key already signed for another User ID');
      keyBinding.set(tp, c.sub);
    }
    return { sub: c.sub, sid: c.sid, clientId: c.iss };
  }

  const challenge = (resource, extra = '') => `Bearer ${resource ? `resource_metadata="${resource}", ` : ''}${extra}`.replace(/, $/, '').trim();

  /** The shared front door for the API and MCP: version, Session, then OAuth (a separate decision). */
  async function guard({ method, url, headers, resourceId, requiredScope, signedOutOk }) {
    const get = headerGetter({ headers });
    const sessionHeader = get('poppy-session');
    const auth = get('authorization');
    const accessToken = auth && /^bearer /i.test(auth) ? auth.slice(7).trim() : null;
    const sessionFail = (status, error, description) => jsonResponse(has('session_401') && error === 'invalid_session' ? 401 : status, { error, error_description: description });
    if (sessionHeader) {
      const v = get('poppy-version');
      if (!has('no_version_check') && !(typeof v === 'string' && /^\d+\.\d+$/.test(v) && v.split('.')[0] === SPEC_VERSION.split('.')[0])) return { response: sessionFail(400, 'version_unsupported', 'Poppy-Version is missing or names a version this Company does not serve') };
    } else if (!signedOutOk && !accessToken) {
      return { response: jsonResponse(400, { error: 'invalid_session', error_description: 'this endpoint relies on Session claims: send Poppy-Session' }) };
    }
    let who = null;
    if (sessionHeader) {
      try { who = await verifySession({ header: sessionHeader, method, url, accessToken }); } catch (e) {
        if (!(e instanceof SessionError)) throw e;
        return { response: sessionFail(400, 'invalid_session', e.message) };
      }
    }
    let claims = null;
    if (accessToken) {
      claims = issuer.verifyAccessToken(accessToken);
      const wrongResource = claims && !has('no_audience_check') && claims.aud !== resourceId && !(resourceId === MCP_URL && has('mcp_accepts_default_token') && claims.aud === COMPANY_ORIGIN);
      if (!claims || wrongResource) {
        return { response: jsonResponse(401, { error: 'invalid_token' }, { 'www-authenticate': challenge(resourceId === MCP_URL ? `${COMPANY_ORIGIN}/.well-known/oauth-protected-resource/mcp` : '', 'error="invalid_token"') }) };
      }
      if (who && who.clientId !== claims.client_id && !has('token_client_mismatch_ok')) return { response: sessionFail(400, 'invalid_session', 'the access token was issued to a different client than the Session iss') };
      if (requiredScope && !has('scope_not_enforced') && !String(claims.scope).split(' ').includes(requiredScope)) {
        return { response: jsonResponse(403, { error: 'insufficient_scope', scope: requiredScope }, { 'www-authenticate': challenge('', `error="insufficient_scope", scope="${requiredScope}"`) }) };
      }
    } else if (requiredScope) {
      return { response: jsonResponse(401, { error: 'insufficient_scope', scope: requiredScope }, { 'www-authenticate': challenge(resourceId === MCP_URL ? `${COMPANY_ORIGIN}/.well-known/oauth-protected-resource/mcp` : '', `scope="${requiredScope}"`) }) };
    }
    return { who, claims, accessToken };
  }

  async function handle(url, init = {}) {
    const u = new URL(url);
    const method = String(init.method || 'GET').toUpperCase();
    const full = `${u.origin}${u.pathname}`;
    if (method === 'GET' && u.pathname === '/.well-known/poppy.json') return jsonResponse(200, poppyJson());
    if (method === 'GET' && u.pathname === '/.well-known/oauth-protected-resource') return jsonResponse(200, protectedResource());
    if (method === 'GET' && u.pathname === '/.well-known/oauth-protected-resource/mcp') return jsonResponse(200, mcpResource());
    if (method === 'GET' && u.pathname === '/openapi.json') return jsonResponse(200, openapi());
    if (method === 'GET' && u.pathname === '/poppy/api/v1/catalog') {
      const g = await guard({ method, url: full, headers: init.headers, resourceId: COMPANY_ORIGIN, signedOutOk: true });
      return g.response ?? jsonResponse(200, { items: [{ sku: 'tent-2p', name: 'Two-person tent' }], signed_in: Boolean(g.claims), sid: g.who?.sid ?? null });
    }
    if (method === 'GET' && u.pathname === '/poppy/api/v1/me') {
      const g = await guard({ method, url: full, headers: init.headers, resourceId: COMPANY_ORIGIN, requiredScope: 'orders:read' });
      return g.response ?? jsonResponse(200, { state: 'signed_in', user_id: g.who?.sub ?? null, session_id: g.who?.sid ?? null, account: g.claims.sub, scopes: String(g.claims.scope).split(' ') });
    }
    if (method === 'POST' && u.pathname === '/mcp') {
      const g = await guard({ method, url: full, headers: init.headers, resourceId: MCP_URL, requiredScope: 'orders:read' });
      return g.response ?? jsonResponse(200, { jsonrpc: '2.0', id: 1, result: { tools: [{ name: 'list_orders', description: 'List your orders' }] } });
    }
    return jsonResponse(404, { error: 'not_found' });
  }

  return { handle, poppyJson, protectedResource, verifySession, replaySize: () => replay.size };
}
