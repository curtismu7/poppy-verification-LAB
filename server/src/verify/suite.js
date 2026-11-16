// The verification suite: checks a Company and its issuer against Personal Agent Protocol 1.0 (published 2026-11-14) and the
// guide's rollout checklist. Each check names the spec section it comes from. Results are pass, fail, warn (a SHOULD or MAY),
// or skip (it needs something this target cannot give, with the reason). A check never throws: a crash is a fail with the message.
import crypto from 'node:crypto';
import { SPEC_VERSION } from '../reference/common.js';

const SPEC = 'https://personalagentprotocol.org/docs/1.0/spec';
export const SPEC_URL = SPEC;
const REJECT_CODES = ['invalid_session', 'version_unsupported', 'session_ended'];

const pass = (detail) => ({ status: 'pass', detail });
const fail = (detail) => ({ status: 'fail', detail });
const warn = (detail) => ({ status: 'warn', detail });
const skip = (detail) => ({ status: 'skip', detail });
const isObj = (x) => x && typeof x === 'object' && !Array.isArray(x);
const pkceOf = () => { const verifier = crypto.randomBytes(32).toString('base64url'); return { verifier, challenge: crypto.createHash('sha256').update(verifier).digest('base64url') }; };

async function json(res) { try { return await res.json(); } catch { return null; } }

/**
 * A Session the Company ought to accept. The probe is the signed-out catalog (a Session, no sign-in) when the target has one;
 * a Company that answers 401/403 for an endpoint that needs sign-in has still accepted the Session.
 */
const accepted = (res, body) => !(res.status === 400 && REJECT_CODES.includes(body?.error)) && !(res.status === 401 && body?.error === 'invalid_session');
const rejected = (res, body) => (res.status === 400 && REJECT_CODES.includes(body?.error)) || (res.status === 401 && body?.error === 'invalid_session');

/** Checks are plain data so the page can list them before they run. `run(ctx)` returns { status, detail }. */
export const CHECKS = [
  // ---- Discovery -------------------------------------------------------------------------------------------------------
  { id: 'disc-poppy-json', group: 'Discovery', title: 'poppy.json is served as JSON at the well-known path', spec: '3', run: (c) => (c.poppy ? pass(`${c.origin}/.well-known/poppy.json`) : fail(c.errors.poppy || 'not readable')) },
  { id: 'disc-https', group: 'Discovery', title: 'Every URL in poppy.json is https', spec: '3', needs: 'poppy', run: (c) => { const bad = [...JSON.stringify(c.poppy).matchAll(/"(https?:\/\/[^"]+)"/g)].map((m) => m[1]).filter((u) => !u.startsWith('https://')); return bad.length ? fail(`not https: ${bad.join(', ')}`) : pass('all https'); } },
  { id: 'disc-version', group: 'Discovery', title: 'protocol_version is major.minor and compatible with 1.x', spec: '3.1, 3.4', needs: 'poppy', run: (c) => (/^\d+\.\d+$/.test(c.poppy.protocol_version ?? '') && c.poppy.protocol_version.split('.')[0] === SPEC_VERSION.split('.')[0] ? pass(`protocol_version ${c.poppy.protocol_version}`) : fail(`protocol_version ${JSON.stringify(c.poppy.protocol_version)}`)) },
  { id: 'disc-domain', group: 'Discovery', title: 'organization.domain is the host that served the document', spec: '3.1', needs: 'poppy', run: (c) => { const u = new URL(c.origin); const want = u.port && u.port !== '443' ? u.host : u.hostname; return String(c.poppy.organization?.domain).toLowerCase() === want.toLowerCase() ? pass(`organization.domain ${c.poppy.organization.domain}`) : fail(`organization.domain ${JSON.stringify(c.poppy.organization?.domain)}, served from ${want}`); } },
  { id: 'disc-channel', group: 'Discovery', title: 'At least one of agent, apis or web is listed', spec: '3.1', needs: 'poppy', run: (c) => (c.poppy.agent || c.poppy.apis?.length || c.poppy.web ? pass('has a channel') : fail('none of agent, apis, web')) },
  { id: 'disc-issuer', group: 'Discovery', title: 'auth.issuer is one of the protected resource authorization servers (required when there are several)', spec: '3.1, 3.2', needs: 'prm', run: (c) => { const servers = c.prm.authorization_servers ?? []; const i = c.poppy.auth?.issuer; if (i === undefined) return servers.length > 1 ? fail('several authorization servers and no auth.issuer') : pass('single authorization server; auth.issuer may be omitted'); return servers.includes(i) ? pass(`auth.issuer ${i}`) : fail(`auth.issuer ${i} is not in authorization_servers`); } },
  { id: 'disc-scope-hints', group: 'Discovery', title: 'Each scope_hints entry has changes (none/reversible/irreversible) and personal_data (boolean)', spec: '4.7', needs: 'poppy', run: (c) => { const h = c.poppy.auth?.scope_hints ?? {}; const bad = Object.entries(h).filter(([, v]) => !(isObj(v) && ['none', 'reversible', 'irreversible'].includes(v.changes) && typeof v.personal_data === 'boolean')).map(([k]) => k); return bad.length ? fail(`bad hints: ${bad.join(', ')}`) : pass(`${Object.keys(h).length} hints`); } },
  { id: 'disc-scope-described', group: 'Discovery', title: 'Each advertised scope has a plain-language description', spec: '4.7', level: 'should', needs: 'poppy', run: (c) => { const s = c.poppy.auth?.scopes ?? {}; const bad = Object.entries(s).filter(([, v]) => typeof v !== 'string' || !v.trim()).map(([k]) => k); return bad.length ? warn(`no description: ${bad.join(', ')}`) : pass(`${Object.keys(s).length} scopes described`); } },
  { id: 'disc-api-types', group: 'Discovery', title: 'apis entries have a type and an https url', spec: '7', needs: 'poppy', run: (c) => { const bad = (c.poppy.apis ?? []).filter((a) => !(typeof a.type === 'string' && typeof a.url === 'string' && a.url.startsWith('https://'))); return bad.length ? fail(`${bad.length} bad apis entries`) : pass(`${(c.poppy.apis ?? []).map((a) => a.type).join(', ') || 'none'}`); } },

  // ---- Protected resource and issuer metadata ----------------------------------------------------------------------------
  { id: 'prm-resource', group: 'Issuer metadata', title: 'Protected resource metadata: resource is exactly the Company origin', spec: '3.2', needs: 'poppy', run: (c) => (c.prm?.resource === c.origin ? pass(`resource ${c.prm.resource}`) : fail(c.errors.prm || `resource ${JSON.stringify(c.prm?.resource)} must be ${c.origin}`)) },
  { id: 'prm-issuer', group: 'Issuer metadata', title: 'The issuer is listed in authorization_servers', spec: '3.2', needs: 'prm', run: (c) => (c.issuer && (c.prm.authorization_servers ?? []).includes(c.issuer) ? pass(c.issuer) : fail('issuer not listed')) },
  { id: 'as-issuer', group: 'Issuer metadata', title: 'AS metadata issuer equals the issuer character for character', spec: '3.2', needs: 'as', run: (c) => (c.as.issuer === c.issuer ? pass(c.as.issuer) : fail(`${JSON.stringify(c.as.issuer)} vs ${c.issuer}`)) },
  { id: 'as-protected-resources', group: 'Issuer metadata', title: 'AS metadata protected_resources lists the Company (the half of the link the guide left out)', spec: '3.2', needs: 'as', run: (c) => (Array.isArray(c.as.protected_resources) && c.as.protected_resources.includes(c.origin) ? pass(`protected_resources ${JSON.stringify(c.as.protected_resources)}`) : fail(`protected_resources ${JSON.stringify(c.as.protected_resources ?? null)} must include ${c.origin} (no path, no trailing slash). PingFederate has no setting for this today.`)) },
  { id: 'as-revocation', group: 'Issuer metadata', title: 'revocation_endpoint is published', spec: '3.2', needs: 'as', run: (c) => (typeof c.as.revocation_endpoint === 'string' ? pass(c.as.revocation_endpoint) : fail('missing')) },
  { id: 'as-refresh-grant', group: 'Issuer metadata', title: 'grant_types_supported includes refresh_token', spec: '3.2', needs: 'as', run: (c) => ((c.as.grant_types_supported ?? []).includes('refresh_token') ? pass('refresh_token listed') : fail(JSON.stringify(c.as.grant_types_supported ?? null))) },
  { id: 'as-auth-endpoint', group: 'Issuer metadata', title: 'authorization_endpoint is present when authorization_code is listed', spec: '3.2', needs: 'as', run: (c) => (!(c.as.grant_types_supported ?? []).includes('authorization_code') || typeof c.as.authorization_endpoint === 'string' ? pass('ok') : fail('authorization_code listed, no authorization_endpoint')) },
  { id: 'as-device', group: 'Issuer metadata', title: 'device_authorization_endpoint is present when the device_code grant is listed (Device Sign-In is advertised here, not in poppy.json)', spec: '3.2, 4.3', needs: 'as', run: (c) => { const dev = (c.as.grant_types_supported ?? []).includes('urn:ietf:params:oauth:grant-type:device_code'); return !dev ? pass('Device Sign-In is not offered') : (typeof c.as.device_authorization_endpoint === 'string' ? pass('offered, endpoint present') : fail('device_code listed, no device_authorization_endpoint')); } },
  { id: 'as-par', group: 'Issuer metadata', title: 'PAR: an endpoint is published whenever PAR is required', spec: '4.2', needs: 'as', run: (c) => (c.as.require_pushed_authorization_requests === true && typeof c.as.pushed_authorization_request_endpoint !== 'string' ? fail('PAR required but no pushed_authorization_request_endpoint') : pass(c.as.pushed_authorization_request_endpoint ? `PAR endpoint present${c.as.require_pushed_authorization_requests ? ' and required' : ''}` : 'PAR not offered')) },
  { id: 'as-endpoints-https', group: 'Issuer metadata', title: 'Every endpoint is https', spec: '3', needs: 'as', run: (c) => { const bad = ['authorization_endpoint', 'token_endpoint', 'revocation_endpoint', 'pushed_authorization_request_endpoint', 'device_authorization_endpoint'].filter((k) => c.as[k] !== undefined && !String(c.as[k]).startsWith('https://')); return bad.length ? fail(`not https: ${bad.join(', ')}`) : pass('all https'); } },
  { id: 'as-algs', group: 'Issuer metadata', title: 'token_endpoint_auth_signing_alg_values_supported lists ES256 and PS384 (a Company MUST accept both)', spec: '4.1', level: 'should', needs: 'as', run: (c) => { const a = c.as.token_endpoint_auth_signing_alg_values_supported ?? []; return a.includes('ES256') && a.includes('PS384') ? pass(a.join(', ')) : warn(`lists ${JSON.stringify(a)}`); } },
  { id: 'as-iss-param', group: 'Issuer metadata', title: 'authorization_response_iss_parameter_supported is true (RFC 9207)', spec: '4.2', level: 'should', needs: 'as', run: (c) => (c.as.authorization_response_iss_parameter_supported === true ? pass('true') : warn('not advertised; the iss check below shows whether it is sent')) },

  // ---- Poppy-Session (needs the agent key; no sign-in) -------------------------------------------------------------------
  { id: 's-valid', group: 'Poppy-Session', title: 'A correct Session is accepted (so the rejections below mean something)', spec: '5.3', needs: 'probe', run: async (c) => { const r = await c.send(); return r.ok ? pass(`HTTP ${r.res.status}`) : fail(`HTTP ${r.res.status} ${JSON.stringify(r.body)}`); } },
  { id: 's-version-missing', group: 'Poppy-Session', title: 'No Poppy-Version: version_unsupported, HTTP 400', spec: '3.4', needs: 'probe', run: async (c) => { const r = await c.send({ omitVersion: true }); return r.res.status === 400 && r.body?.error === 'version_unsupported' ? pass('400 version_unsupported') : fail(`HTTP ${r.res.status} ${JSON.stringify(r.body)}`); } },
  { id: 's-version-major', group: 'Poppy-Session', title: 'Poppy-Version 2.0 (another major): version_unsupported', spec: '3.4', needs: 'probe', run: async (c) => { const r = await c.send({ version: '2.0' }); return r.res.status === 400 && r.body?.error === 'version_unsupported' ? pass('400 version_unsupported') : fail(`HTTP ${r.res.status} ${JSON.stringify(r.body)}`); } },
  ...[
    ['s-aud', 'Session aud is another Company: refused', { claims: { aud: 'https://other.example' } }],
    ['s-htu', 'Session htu is another URL: refused', { claims: { htu: 'https://company.example/elsewhere' } }],
    ['s-htm', 'Session htm is another method: refused', { claims: { htm: 'DELETE' } }],
    ['s-iat-old', 'Session iat an hour old: refused', { claims: { iat: -3600 } }],
    ['s-iat-future', 'Session iat an hour ahead: refused', { claims: { iat: 3600 } }],
    ['s-typ-session', 'Session typ is not poppy-session+jwt: refused', { header: { typ: 'JWT' } }],
    ['s-alg-none', 'alg none: refused', { header: { alg: 'none' } }],
    ['s-alg-hs256', 'alg HS256: refused', { header: { alg: 'HS256' } }],
    ['s-no-delegation', 'Signed directly with a jwks_uri key, no delegation: refused', { noDelegation: true }],
    ['s-delegation-24h', 'A delegation that lasts 48 hours: refused', { delegation: { lifetime: 48 * 3600 } }],
    ['s-delegation-expired', 'An expired delegation: refused', { delegation: { lifetime: -1 } }],
    ['s-delegation-typ', 'Delegation typ is not poppy-delegation+jwt: refused', { delegation: { typ: 'JWT' } }],
    ['s-delegation-rogue', 'Delegation signed by a key no jwks_uri publishes: refused', { delegation: { rogue: true } }],
    ['s-ath-no-token', 'ath present but the request has no access token: refused', { claims: { ath: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' } }],
  ].map(([id, title, spec]) => ({ id, group: 'Poppy-Session', title, spec: spec.header?.alg ? '5.2, guides' : '5.2, 5.3', needs: 'probe', run: async (c) => { const r = await c.send(spec); return rejected(r.res, r.body) ? pass(`refused: HTTP ${r.res.status} ${r.body?.error ?? ''}`) : fail(`accepted: HTTP ${r.res.status}`); } })),
  { id: 's-replay', group: 'Poppy-Session', title: 'The same Session jti twice: the second is refused', spec: '5.3', level: 'should', needs: 'probe', run: async (c) => { const header = c.kit.session({ method: 'GET', url: c.probeUrl, ...{} }); const a = await c.sendRaw(header); const b = await c.sendRaw(header); return accepted(a.res, a.body) && rejected(b.res, b.body) ? pass('second use refused') : (!accepted(a.res, a.body) ? skip('the first use was refused, so replay cannot be judged') : warn('a reused jti was accepted (the spec says a Company MAY reject a reuse; the guide asks you to)')); } },
  { id: 's-status-400', group: 'Poppy-Session', title: 'Session failures are HTTP 400 with a JSON error, not 401 (so OAuth libraries keep a valid token)', spec: '5.3, 7', needs: 'probe', run: async (c) => { const r = await c.send({ claims: { aud: 'https://other.example' } }); return r.res.status === 400 && REJECT_CODES.includes(r.body?.error) ? pass('400 invalid_session') : (rejected(r.res, r.body) ? fail(`HTTP ${r.res.status}: use 400`) : skip('the bad Session was not refused (see its own check)')); } },
  { id: 's-ps384', group: 'Poppy-Session', title: 'A delegation signed with PS384 is accepted (Companies MUST accept ES256 and PS384)', spec: '5.2', needs: 'probe', run: async (c) => { if (!c.kit.main.ps) return skip('the real agent publishes an ES256 key only'); const r = await c.send({ delegation: { alg: 'PS384' } }); return accepted(r.res, r.body) ? pass(`HTTP ${r.res.status}`) : fail(`refused: HTTP ${r.res.status} ${JSON.stringify(r.body)}`); } },

  // ---- Sign-in, tokens, resources (needs a reference issuer this process can drive; a real issuer needs a person) ----------
  { id: 'o-assertion-aud', group: 'Sign-in and tokens', title: 'Client assertion aud = the token endpoint URL: refused (aud must be the issuer)', spec: '4.1', needs: 'signin', run: async (c) => { const r = await c.tokenRaw({ assertion: { aud: `${c.issuer}/token` } }); return r.body?.error === 'invalid_client' ? pass(`refused: ${r.body.error_description ?? r.body.error}`) : fail(`the assertion was accepted (HTTP ${r.res.status} ${r.body?.error ?? ''})`); } },
  { id: 'o-assertion-lifetime', group: 'Sign-in and tokens', title: 'Client assertion lasting an hour: refused (at most 5 minutes)', spec: '4.1', level: 'should', needs: 'signin', run: async (c) => { const r = await c.tokenRaw({ assertion: { lifetime: 3600 } }); return r.body?.error === 'invalid_client' ? pass('refused') : warn('accepted (a Company MAY reject more than 5 minutes)'); } },
  { id: 'o-assertion-replay', group: 'Sign-in and tokens', title: 'Client assertion jti reused: refused', spec: '4.1', level: 'should', needs: 'signin', run: async (c) => { const jti = `reuse-${Math.random().toString(36).slice(2)}`; await c.tokenRaw({ assertion: { jti } }); const r = await c.tokenRaw({ assertion: { jti } }); return r.body?.error === 'invalid_client' ? pass('second use refused') : warn('accepted twice (a Company MAY reject a reused jti)'); } },
  { id: 'o-assertion-ps384', group: 'Sign-in and tokens', title: 'A PS384 client assertion is accepted', spec: '4.1', needs: 'signin', run: async (c) => { if (!c.kit.main.ps) return skip('the real agent has no PS384 key'); const s = await c.signIn({ assertionAlg: 'PS384' }); return s.ok ? pass('signed in with a PS384 assertion') : fail(`refused: ${s.reason}`); } },
  { id: 'o-iss-success', group: 'Sign-in and tokens', title: 'The authorization response carries iss (RFC 9207)', spec: '4.2', needs: 'signin', run: async (c) => { const s = await c.signIn({}); return !s.ok ? skip(`sign-in failed: ${s.reason}`) : (s.iss === c.issuer ? pass(`iss ${s.iss}`) : fail(`iss ${JSON.stringify(s.iss)}`)); } },
  { id: 'o-iss-error', group: 'Sign-in and tokens', title: 'An error response (access_denied) carries iss too', spec: '4.2', needs: 'signin', run: async (c) => { const s = await c.signIn({ deny: true }); return s.error === 'access_denied' ? (s.iss === c.issuer ? pass('access_denied with iss') : fail(`access_denied, iss ${JSON.stringify(s.iss)}`)) : skip(`no access_denied redirect: ${s.reason ?? ''}`); } },
  { id: 'o-pkce', group: 'Sign-in and tokens', title: 'A code redeemed without the PKCE verifier: refused', spec: '4.2', needs: 'signin', run: async (c) => { const s = await c.signIn({ wrongVerifier: true }); return s.ok ? fail('a token was issued without the right code_verifier') : pass(`refused: ${s.reason}`); } },
  { id: 'o-redirect-exact', group: 'Sign-in and tokens', title: 'redirect_uri that only starts with a registered one: not accepted', spec: '4.2', needs: 'signin', run: async (c) => { const s = await c.signIn({ redirectSuffix: '/evil', stopAtAuthorize: true }); return s.kind === 'consent' ? fail('the authorization request was accepted') : pass('refused'); } },
  { id: 'o-scope-subset', group: 'Sign-in and tokens', title: 'The granted scopes never exceed the requested ones', spec: '4.7', needs: 'signin', run: async (c) => { const s = await c.signIn({ scope: 'orders:read' }); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const extra = String(s.scope).split(' ').filter((x) => x && x !== 'orders:read'); return extra.length ? fail(`granted ${s.scope}; asked orders:read`) : pass(`granted ${s.scope}`); } },
  { id: 'o-cimd-redirect', group: 'Sign-in and tokens', title: 'Client metadata that sits behind a redirect: refused (redirects are not followed)', spec: '4.1', needs: 'signin', run: async (c) => { const s = await c.signIn({ clientPath: '/redirecting/client.json', stopAtAuthorize: true }); return s.kind === 'consent' ? fail('the redirect was followed') : pass('refused'); } },
  { id: 'o-cimd-jwks-host', group: 'Sign-in and tokens', title: 'jwks_uri on another host than the client_id: refused', spec: '4.1', needs: 'signin', run: async (c) => { const s = await c.signIn({ clientPath: '/otherhost/client.json', stopAtAuthorize: true }); return s.kind === 'consent' ? fail('a jwks_uri on another host was accepted') : pass('refused'); } },
  { id: 'o-cimd-mismatch', group: 'Sign-in and tokens', title: 'A document whose client_id differs from its own URL: refused', spec: '4.1', needs: 'signin', run: async (c) => { const s = await c.signIn({ clientPath: '/mismatch/client.json', stopAtAuthorize: true }); return s.kind === 'consent' ? fail('accepted') : pass('refused'); } },
  { id: 'o-cimd-loopback', group: 'Sign-in and tokens', title: 'A client_id that names a loopback or private address: refused without fetching it', spec: '3, 10', needs: 'signin', run: async (c) => { const s = await c.signIn({ clientUrl: 'https://127.0.0.1/client.json', stopAtAuthorize: true }); return s.kind === 'consent' ? fail('accepted') : pass('refused'); } },
  { id: 'o-refresh', group: 'Sign-in and tokens', title: 'Refresh works and replaces the refresh token; the old one then fails', spec: '4.4', needs: 'signin', run: async (c) => { const s = await c.signIn({}); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const a = await c.refresh(s.refresh_token); if (!a.ok) return fail(`refresh refused: ${a.reason}`); const old = await c.refresh(s.refresh_token); return old.ok ? fail('the replaced refresh token still works') : pass('refreshed; the replaced token is refused'); } },
  { id: 'o-revoke', group: 'Sign-in and tokens', title: 'After revocation the refresh token is invalid_grant', spec: '4.6, 5.5', needs: 'signin', run: async (c) => { const s = await c.signIn({}); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const rv = await c.revoke(s.refresh_token); if (!rv.ok) return fail(`revocation refused: ${rv.reason}`); const r = await c.refresh(s.refresh_token); return r.ok ? fail('a revoked refresh token still works') : pass('refused after revocation'); } },
  { id: 'a-signed-in', group: 'Resources and tokens', title: 'A signed-in call with a matching Session succeeds', spec: '5.3, 7', needs: 'signin', run: async (c) => { const s = await c.signIn({}); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const r = await c.send({ path: c.signedInPath, accessToken: s.access_token }); return r.res.status === 200 ? pass('HTTP 200') : fail(`HTTP ${r.res.status} ${JSON.stringify(r.body)}`); } },
  { id: 'a-ath', group: 'Resources and tokens', title: 'ath of another token: refused', spec: '5.3', needs: 'signin', run: async (c) => { const s = await c.signIn({}); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const r = await c.send({ path: c.signedInPath, accessToken: s.access_token, claims: { ath: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' } }); return rejected(r.res, r.body) ? pass('refused') : fail(`HTTP ${r.res.status}: ath was not checked`); } },
  { id: 'a-scope', group: 'Resources and tokens', title: 'A token without orders:read is insufficient_scope (HTTP 403)', spec: '4.7, 7', needs: 'signin', run: async (c) => { const s = await c.signIn({ scope: 'orders:write' }); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const r = await c.send({ path: c.signedInPath, accessToken: s.access_token }); return r.res.status === 403 && r.body?.error === 'insufficient_scope' ? pass('403 insufficient_scope') : fail(`HTTP ${r.res.status} ${JSON.stringify(r.body)}`); } },
  { id: 'a-token-client', group: 'Resources and tokens', title: 'A token issued to another client than the Session iss: refused', spec: '5.3', needs: 'signin', run: async (c) => { if (!c.kit.other) return skip('needs a second agent identity'); const s = await c.signIn({}); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const r = await c.send({ path: c.signedInPath, accessToken: s.access_token, identity: c.kit.other }); return rejected(r.res, r.body) ? pass('refused') : fail(`HTTP ${r.res.status}: another agent used this token`); } },
  { id: 'a-mcp-own-token', group: 'Resources and tokens', title: 'MCP: a token for the MCP resource works there', spec: '4.5, 7', needs: 'signin', run: async (c) => { const s = await c.signIn({ resource: c.mcpUrl }); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const r = await c.send({ method: 'POST', path: '/mcp', accessToken: s.access_token }); return r.res.status === 200 ? pass('HTTP 200') : fail(`HTTP ${r.res.status} ${JSON.stringify(r.body)}`); } },
  { id: 'a-mcp-default-token', group: 'Resources and tokens', title: 'MCP: the default Company token is refused there, with a resource_metadata challenge', spec: '4.5, 7', needs: 'signin', run: async (c) => { const s = await c.signIn({}); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const r = await c.send({ method: 'POST', path: '/mcp', accessToken: s.access_token }); const ch = r.res.headers.get('www-authenticate') ?? ''; return r.res.status === 401 && /resource_metadata=/.test(ch) ? pass('401 invalid_token with resource_metadata') : fail(`HTTP ${r.res.status}; challenge ${JSON.stringify(ch)}`); } },
  { id: 'a-api-mcp-token', group: 'Resources and tokens', title: 'The API refuses a token issued for the MCP resource (audience)', spec: '4.5', needs: 'signin', run: async (c) => { const s = await c.signIn({ resource: c.mcpUrl }); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const r = await c.send({ path: c.signedInPath, accessToken: s.access_token }); return r.res.status === 401 ? pass('refused: 401 invalid_token') : fail(`HTTP ${r.res.status}: a token for another resource was accepted`); } },
];

export const CHECK_LIST = CHECKS.map(({ id, group, title, spec, level, needs }) => ({ id, group, title, spec, level: level ?? 'must', needs: needs ?? null }));

/**
 * Run the suite. `target` supplies: origin, fetch, kit, probePath, and (Mock only) `driver` with the reference issuer so sign-in
 * based checks can run. Discovery data is read once and shared.
 */
export async function runSuite(target, { only } = {}) {
  const { origin, kit } = target;
  const fetchImpl = target.fetch;
  const errors = {};
  const get = async (url, key) => {
    try {
      const res = await fetchImpl(url, { headers: { accept: 'application/json' }, redirect: 'manual' });
      if (res.status !== 200) { errors[key] = `${url} answered ${res.status}`; return null; }
      const body = await json(res);
      if (!isObj(body)) { errors[key] = `${url} is not a JSON object`; return null; }
      return body;
    } catch (e) { errors[key] = `${url}: ${String(e.message).slice(0, 120)}`; return null; }
  };
  const poppy = await get(`${origin}/.well-known/poppy.json`, 'poppy');
  const prm = poppy ? await get(`${origin}/.well-known/oauth-protected-resource`, 'prm') : null;
  const issuer = poppy?.auth?.issuer ?? (prm?.authorization_servers?.length === 1 ? prm.authorization_servers[0] : undefined);
  const as = issuer ? (await get(`${issuer}/.well-known/oauth-authorization-server`, 'as')) ?? null : null;

  const probePath = target.probePath;
  const probeUrl = `${origin}${probePath}`;
  const send = async ({ path = probePath, method = 'GET', accessToken, omitVersion, version = SPEC_VERSION, identity, claims = {}, header = {}, noDelegation, delegation: d, ...rest } = {}) => {
    const url = `${origin}${path}`;
    // Overrides that depend on the clock are written relative to now in the check list (iat: -3600 means an hour ago).
    const t = Math.floor(Date.now() / 1000);
    const cl = { ...claims };
    if (typeof cl.iat === 'number' && Math.abs(cl.iat) <= 7200) cl.iat = t + cl.iat;
    let delegation;
    if (d) {
      const ident = identity ?? kit.main;
      delegation = d.lifetime < 0
        ? kit.delegationJwt({ identity: ident, lifetime: 60, iat: t - 7200 }) // issued two hours ago, lasted a minute: expired
        : kit.delegationJwt({ identity: ident, lifetime: d.lifetime ?? 3600, iat: t, typ: d.typ, alg: d.alg, signer: d.rogue ? kit.rogue : null });
    }
    const session = kit.session({ method, url, accessToken, claims: cl, header, noDelegation, delegation, identity: identity ?? kit.main, ...rest });
    return sendRaw(session, { url, method, accessToken, omitVersion, version });
  };
  const sendRaw = async (session, { url = probeUrl, method = 'GET', accessToken, omitVersion = false, version = SPEC_VERSION } = {}) => {
    const headers = { accept: 'application/json', 'poppy-session': session, ...(omitVersion ? {} : { 'poppy-version': version }), ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}) };
    try {
      const res = await fetchImpl(url, { method, headers, redirect: 'manual' });
      const body = await json(res.clone());
      return { res, body, ok: accepted(res, body) };
    } catch (e) { return { res: { status: 0, headers: new Headers() }, body: { error: 'network', message: e.message }, ok: false }; }
  };

  const driver = target.driver ?? null;
  const ctx = { origin, kit, poppy, prm, as, issuer, errors, probePath, probeUrl, send, sendRaw, mcpUrl: driver?.mcpUrl, signedInPath: driver?.signedInPath ?? '/poppy/api/v1/me' };
  if (driver) Object.assign(ctx, driver.methods({ origin, kit, issuer }));

  const results = [];
  for (const chk of CHECKS) {
    if (only && !only.includes(chk.id)) continue;
    let r;
    const missing = chk.needs === 'poppy' && !poppy ? 'poppy.json could not be read' : chk.needs === 'prm' && !prm ? 'protected resource metadata could not be read' : chk.needs === 'as' && !as ? `issuer metadata could not be read${errors.as ? ` (${errors.as})` : ''}` : chk.needs === 'probe' && !target.probeReady ? (target.probeReason ?? 'no probe') : chk.needs === 'signin' && !driver ? 'needs a person to sign in: use Real mode on the Run it tab, then re-run (this suite drives sign-in itself only against the reference issuer)' : null;
    if (missing) r = skip(missing);
    else {
      try { r = await chk.run(ctx); } catch (e) { r = fail(`the check crashed: ${String(e.message).slice(0, 160)}`); }
    }
    results.push({ id: chk.id, group: chk.group, title: chk.title, spec: chk.spec, level: chk.level ?? 'must', ...r });
  }
  // A negative Session check is meaningful only if the correct Session was accepted. Otherwise say so instead of passing by accident.
  const valid = results.find((r) => r.id === 's-valid');
  if (valid && valid.status !== 'pass') for (const r of results) if (r.group === 'Poppy-Session' && r.id !== 's-valid' && r.status === 'pass') { r.status = 'skip'; r.detail = `inconclusive: a correct Session was not accepted, so a refusal proves nothing (${r.detail})`; }
  const count = (s) => results.filter((r) => r.status === s).length;
  return { spec: `Personal Agent Protocol ${SPEC_VERSION}`, specUrl: SPEC, origin, issuer: issuer ?? null, results, summary: { pass: count('pass'), fail: count('fail'), warn: count('warn'), skip: count('skip'), total: results.length }, conformant: count('fail') === 0 };
}
