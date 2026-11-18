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
const plausible = (res) => (res.status >= 200 && res.status < 300) || res.status === 401 || res.status === 403;
const accepted = (res, body) => plausible(res) && !(res.status === 401 && body?.error === 'invalid_session');
const describe = (r) => `HTTP ${r.res.status}${r.body?.error ? ` ${r.body.error}` : ''}`;
const sessionRefused = (r) => (r.res.status === 400 && REJECT_CODES.includes(r.body?.error)) || (r.res.status === 401 && r.body?.error === 'invalid_session');
const rejected = (res, body) => (res.status === 400 && REJECT_CODES.includes(body?.error)) || (res.status === 401 && body?.error === 'invalid_session');
const hasScopeChallenge = (r) => r.body?.error === 'insufficient_scope' || /insufficient_scope/.test(r.res.headers.get?.('www-authenticate') ?? '');

/** Checks are plain data so the page can list them before they run. `run(ctx)` returns { status, detail }. */
export const CHECKS = [
  // ---- Discovery -------------------------------------------------------------------------------------------------------
  { id: 'disc-poppy-json', group: 'Discovery', title: 'poppy.json is served as JSON at the well-known path', spec: '3', run: (c) => (c.poppy ? pass(`${c.origin}/.well-known/poppy.json`) : fail(c.errors.poppy || 'not readable')) },
  { id: 'disc-https', group: 'Discovery', title: 'Every URL in poppy.json is https', spec: '3', needs: 'poppy', run: (c) => { const bad = [...JSON.stringify(c.poppy).matchAll(/"(https?:\/\/[^"]+)"/g)].map((m) => m[1]).filter((u) => !u.startsWith('https://')); return bad.length ? fail(`not https: ${bad.join(', ')}`) : pass('all https'); } },
  { id: 'disc-version', group: 'Discovery', title: 'protocol_version is major.minor and compatible with 1.x', spec: '3.1, 3.4', needs: 'poppy', run: (c) => (/^\d+\.\d+$/.test(c.poppy.protocol_version ?? '') && c.poppy.protocol_version.split('.')[0] === SPEC_VERSION.split('.')[0] ? pass(`protocol_version ${c.poppy.protocol_version}`) : fail(`protocol_version ${JSON.stringify(c.poppy.protocol_version)}`)) },
  { id: 'disc-domain', group: 'Discovery', title: 'organization.domain is the host that served the document', spec: '3.1', needs: 'poppy', run: (c) => { const u = new URL(c.origin); const want = u.port && u.port !== '443' ? u.host : u.hostname; return String(c.poppy.organization?.domain).toLowerCase() === want.toLowerCase() ? pass(`organization.domain ${c.poppy.organization.domain}`) : fail(`organization.domain ${JSON.stringify(c.poppy.organization?.domain)}, served from ${want}`); } },
  { id: 'disc-channel', group: 'Discovery', title: 'At least one of agent, apis or web is listed', spec: '3.1', needs: 'poppy', run: (c) => (c.poppy.agent || c.poppy.apis?.length || c.poppy.web ? pass('has a channel') : fail('none of agent, apis, web')) },
  { id: 'disc-issuer', group: 'Discovery', title: 'auth.issuer is one of the protected resource authorization servers (required when there are several)', spec: '3.1, 3.2', needs: 'poppy', run: (c) => { if (!c.prm) return c.poppy.auth?.issuer ? fail(`auth.issuer ${c.poppy.auth.issuer} but no protected resource metadata (${c.errors.prm ?? 'unreadable'})`) : skip('no issuer: nothing to link');  const servers = c.prm.authorization_servers ?? []; const i = c.poppy.auth?.issuer; if (i === undefined) return servers.length > 1 ? fail('several authorization servers and no auth.issuer') : pass('single authorization server; auth.issuer may be omitted'); return servers.includes(i) ? pass(`auth.issuer ${i}`) : fail(`auth.issuer ${i} is not in authorization_servers`); } },
  { id: 'disc-scope-hints', group: 'Discovery', title: 'Each scope_hints entry has changes (none/reversible/irreversible) and personal_data (boolean)', spec: '4.7', needs: 'poppy', run: (c) => { const h = c.poppy.auth?.scope_hints ?? {}; const bad = Object.entries(h).filter(([, v]) => !(isObj(v) && ['none', 'reversible', 'irreversible'].includes(v.changes) && typeof v.personal_data === 'boolean')).map(([k]) => k); return bad.length ? fail(`bad hints: ${bad.join(', ')}`) : pass(`${Object.keys(h).length} hints`); } },
  { id: 'disc-scope-described', group: 'Discovery', title: 'Each advertised scope has a plain-language description', spec: '4.7', level: 'should', needs: 'poppy', run: (c) => { const s = c.poppy.auth?.scopes ?? {}; const bad = Object.entries(s).filter(([, v]) => typeof v !== 'string' || !v.trim()).map(([k]) => k); return bad.length ? warn(`no description: ${bad.join(', ')}`) : pass(`${Object.keys(s).length} scopes described`); } },
  { id: 'disc-api-types', group: 'Discovery', title: 'apis entries have a type and an https url', spec: '7', needs: 'poppy', run: (c) => { const bad = (c.poppy.apis ?? []).filter((a) => !(typeof a.type === 'string' && typeof a.url === 'string' && a.url.startsWith('https://'))); return bad.length ? fail(`${bad.length} bad apis entries`) : pass(`${(c.poppy.apis ?? []).map((a) => a.type).join(', ') || 'none'}`); } },

  // ---- Protected resource and issuer metadata ----------------------------------------------------------------------------
  { id: 'prm-resource', group: 'Issuer metadata', title: 'Protected resource metadata: resource is exactly the Company origin', spec: '3.2', needs: 'poppy', run: (c) => (c.prm?.resource === c.origin ? pass(`resource ${c.prm.resource}`) : (!c.prm && /answered 404/.test(c.errors.prm ?? '') && !c.poppy.auth?.issuer ? pass('no protected resource metadata and no auth.issuer: a Company with no sign-in (spec 3.2)') : fail(c.errors.prm || `resource ${JSON.stringify(c.prm?.resource)} must be ${c.origin}`))) },
  { id: 'prm-issuer', group: 'Issuer metadata', title: 'The issuer is listed in authorization_servers', spec: '3.2', needs: 'prm', run: (c) => (c.issuer && (c.prm.authorization_servers ?? []).includes(c.issuer) ? pass(c.issuer) : fail('issuer not listed')) },
  { id: 'as-issuer', group: 'Issuer metadata', title: 'AS metadata issuer equals the issuer character for character', spec: '3.2', needs: 'as', run: (c) => (c.as.issuer === c.issuer ? pass(c.as.issuer) : fail(`${JSON.stringify(c.as.issuer)} vs ${c.issuer}`)) },
  { id: 'as-protected-resources', group: 'Issuer metadata', title: 'AS metadata protected_resources lists the Company (the half of the link the guide left out)', spec: '3.2', needs: 'as', run: (c) => (Array.isArray(c.as.protected_resources) && c.as.protected_resources.map((x) => String(x).replace(/^(https?:\/\/)([^/]+)/i, (_, a, h) => a.toLowerCase() + h.toLowerCase())).includes(c.origin.replace(/^(https?:\/\/)([^/]+)/i, (_, a, h) => a.toLowerCase() + h.toLowerCase())) ? pass(`protected_resources ${JSON.stringify(c.as.protected_resources)}`) : fail(`protected_resources ${JSON.stringify(c.as.protected_resources ?? null)} must include ${c.origin} (no path, no trailing slash). PingFederate has no setting for this today.`)) },
  { id: 'as-token-endpoint', group: 'Issuer metadata', title: 'token_endpoint is published (a required field)', spec: '3.2', needs: 'as', run: (c) => (typeof c.as.token_endpoint === 'string' ? pass(c.as.token_endpoint) : fail('missing')) },
  { id: 'as-revocation', group: 'Issuer metadata', title: 'revocation_endpoint is published', spec: '3.2', needs: 'as', run: (c) => (typeof c.as.revocation_endpoint === 'string' ? pass(c.as.revocation_endpoint) : fail('missing')) },
  { id: 'as-refresh-grant', group: 'Issuer metadata', title: 'grant_types_supported includes refresh_token', spec: '3.2', needs: 'as', run: (c) => ((c.as.grant_types_supported ?? []).includes('refresh_token') ? pass('refresh_token listed') : fail(JSON.stringify(c.as.grant_types_supported ?? null))) },
  { id: 'as-auth-endpoint', group: 'Issuer metadata', title: 'authorization_endpoint is present when authorization_code is listed', spec: '3.2', needs: 'as', run: (c) => (!(c.as.grant_types_supported ?? []).includes('authorization_code') || typeof c.as.authorization_endpoint === 'string' ? pass('ok') : fail('authorization_code listed, no authorization_endpoint')) },
  { id: 'as-device', group: 'Issuer metadata', title: 'device_authorization_endpoint is present when the device_code grant is listed (Device Sign-In is advertised here, not in poppy.json)', spec: '3.2, 4.3', needs: 'as', run: (c) => { const dev = (c.as.grant_types_supported ?? []).includes('urn:ietf:params:oauth:grant-type:device_code'); return !dev ? pass('Device Sign-In is not offered') : (typeof c.as.device_authorization_endpoint === 'string' ? pass('offered, endpoint present') : fail('device_code listed, no device_authorization_endpoint')); } },
  { id: 'as-par', group: 'Issuer metadata', title: 'PAR: an endpoint is published whenever PAR is required', spec: '4.2', needs: 'as', run: (c) => (c.as.require_pushed_authorization_requests === true && typeof c.as.pushed_authorization_request_endpoint !== 'string' ? fail('PAR required but no pushed_authorization_request_endpoint') : pass(c.as.pushed_authorization_request_endpoint ? `PAR endpoint present${c.as.require_pushed_authorization_requests ? ' and required' : ''}` : 'PAR not offered')) },
  { id: 'as-endpoints-https', group: 'Issuer metadata', title: 'Every endpoint is https', spec: '3', needs: 'as', run: (c) => { const bad = ['authorization_endpoint', 'token_endpoint', 'revocation_endpoint', 'pushed_authorization_request_endpoint', 'device_authorization_endpoint'].filter((k) => c.as[k] !== undefined && !String(c.as[k]).startsWith('https://')); return bad.length ? fail(`not https: ${bad.join(', ')}`) : pass('all https'); } },
  { id: 'as-algs', group: 'Issuer metadata', title: 'token_endpoint_auth_signing_alg_values_supported lists ES256 and PS384 (a Company MUST accept both)', spec: '4.1', level: 'should', needs: 'as', run: (c) => { const a = c.as.token_endpoint_auth_signing_alg_values_supported ?? []; return a.includes('ES256') && a.includes('PS384') ? pass(a.join(', ')) : warn(`lists ${JSON.stringify(a)}`); } },
  { id: 'as-iss-param', group: 'Issuer metadata', title: 'authorization_response_iss_parameter_supported is true (RFC 9207)', spec: '4.2', level: 'should', needs: 'as', run: (c) => (c.as.authorization_response_iss_parameter_supported === true ? pass('true') : warn('not advertised; the iss check below shows whether it is sent')) },

  // ---- Poppy-Session (needs the agent key; no sign-in) -------------------------------------------------------------------
  { id: 's-valid', group: 'Poppy-Session', title: 'A correct Session is accepted (so the rejections below mean something)', spec: '5.3', needs: 'probe', run: async (c) => { const r = await c.send(); const wellFormed = r.body !== null || (r.res.headers.get?.('www-authenticate') ?? '') !== ''; return r.ok && wellFormed ? pass(`HTTP ${r.res.status}`) : r.ok ? fail(`HTTP ${r.res.status} with a body that is neither JSON nor a WWW-Authenticate challenge: this is not a Poppy API answer`) : fail(`${describe(r)}: a correct Session got an answer that is not a 2xx, 401 or 403${r.body?.error === 'network' ? ` (${r.body.message})` : ''}`); } },
  { id: 's-verifies', group: 'Poppy-Session', title: 'A Session that is not a JWT is refused (the endpoint verifies the header)', spec: '5.3', needs: 'probe', run: async (c) => { const r = await c.sendRaw('not-a-jwt'); return sessionRefused(r) ? pass(`refused: ${describe(r)}`) : (c.sessionClaimsEndpoint ? fail(`accepted: ${describe(r)}`) : warn(`${describe(r)}: this endpoint does not verify Poppy-Session. Spec 5.3 lets an endpoint that uses no Session claims skip it, so the checks below are skipped here; choose a probe path that relies on Session claims`)); } },
  { id: 's-version-missing', group: 'Poppy-Session', title: 'No Poppy-Version: version_unsupported, HTTP 400', spec: '3.4', needs: 'session', run: async (c) => { const r = await c.send({ omitVersion: true }); return r.res.status === 400 && r.body?.error === 'version_unsupported' ? pass('400 version_unsupported') : fail(`HTTP ${r.res.status} ${JSON.stringify(r.body)}`); } },
  { id: 's-version-major', group: 'Poppy-Session', title: 'Poppy-Version 2.0 (another major): version_unsupported', spec: '3.4', needs: 'session', run: async (c) => { const r = await c.send({ version: '2.0' }); return r.res.status === 400 && r.body?.error === 'version_unsupported' ? pass('400 version_unsupported') : fail(`HTTP ${r.res.status} ${JSON.stringify(r.body)}`); } },
  ...[
    ['s-aud', 'Session aud is another Company: refused', () => ({ claims: { aud: 'https://other.example' } })],
    ['s-aud-slash', 'Session aud with a trailing slash: refused (character for character)', (c) => ({ claims: { aud: `${c.companyId}/` } })],
    ['s-aud-array', 'Session aud as an array holding the Company: refused (a single string)', (c) => ({ claims: { aud: [c.companyId] } })],
    ['s-htu', 'Session htu is another URL: refused', () => ({ claims: { htu: 'https://company.example/elsewhere' } })],
    ['s-htu-suffix', 'Session htu is the URL plus extra path: refused (exact match)', (c) => ({ claims: { htu: `${c.probeUrl}/extra` } })],
    ['s-htu-truncated', 'Session htu is a prefix of the URL: refused (exact match)', (c) => ({ claims: { htu: c.probeUrl.slice(0, -1) } })],
    ['s-htu-host', 'Session htu names another host with the same path: refused', (c) => ({ claims: { htu: `https://other.example${new URL(c.probeUrl).pathname}` } })],
    ['s-htu-case', 'Session htu with the path in other letter case: refused (the path is case-sensitive)', (c) => ({ claims: { htu: `${new URL(c.probeUrl).origin}${new URL(c.probeUrl).pathname.toUpperCase()}` } })],
    ['s-htm', 'Session htm is another method: refused', () => ({ claims: { htm: 'DELETE' } })],
    ['s-iat-old', 'Session iat an hour old: refused', () => ({ claims: { iat: -3600 } })],
    ['s-iat-future', 'Session iat an hour ahead: refused', () => ({ claims: { iat: 3600 } })],
    ['s-typ-session', 'Session typ is not poppy-session+jwt: refused', () => ({ header: { typ: 'JWT' } })],
    ['s-alg-none', 'alg none: refused', () => ({ header: { alg: 'none' } })],
    ['s-alg-hs256', 'alg HS256: refused', () => ({ header: { alg: 'HS256' } })],
    ['s-kid', 'Session kid is not the delegated key thumbprint: refused', () => ({ header: { kid: 'not-the-thumbprint' } })],
    ['s-no-delegation', 'Signed directly with a jwks_uri key, no delegation: refused', () => ({ noDelegation: true })],
    ['s-delegation-24h', 'A delegation that lasts 48 hours: refused', () => ({ delegation: { lifetime: 48 * 3600 } })],
    ['s-delegation-expired', 'An expired delegation: refused', () => ({ delegation: { lifetime: -1 } })],
    ['s-delegation-typ', 'Delegation typ is not poppy-delegation+jwt: refused', () => ({ delegation: { typ: 'JWT' } })],
    ['s-delegation-rogue', 'Delegation signed by a key no jwks_uri publishes (unknown kid): refused', () => ({ delegation: { rogue: true } })],
    ['s-delegation-forged', 'Delegation that names the REAL jwks kid but is signed by another key: refused (the signature is checked, not just the kid)', () => ({ delegation: { forged: 'rogue' } })],
    ['s-delegation-selfsigned', 'Delegation signed by the delegated key itself under the real kid: refused', () => ({ delegation: { forged: 'delegated' } })],
    ['s-delegation-iss', 'Delegation iss differs from the Session iss: refused', (c) => (c.kit.other ? { delegation: { issOther: true } } : null)],
    ['s-ath-no-token', 'ath present but the request has no access token: refused', () => ({ claims: { ath: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' } })],
  ].map(([id, title, make]) => ({ id, group: 'Poppy-Session', title, spec: id.includes('alg') || id.includes('typ') ? '5.2, guides' : '5.2, 5.3', needs: 'session', run: async (c) => { const spec = make(c); if (!spec) return skip('needs a second agent identity'); const r = await c.send(spec); return sessionRefused(r) ? pass(`refused: ${describe(r)}`) : fail(`not refused: ${describe(r)}`); } })),
  // Spec 5.2 puts "MUST NOT contain private key members" on the delegation the AGENT builds; the Company's verification steps do not
  // require it to refuse one. Refusing is a sensible safeguard, so a Company that accepts it gets a warning, never a failure.
  { id: 's-delegation-cnf-private', group: 'Poppy-Session', title: 'A delegation whose cnf.jwk carries private key members: refused (the MUST NOT binds the agent; a Company refusing it is a safeguard)', spec: '5.2', level: 'should', needs: 'session', run: async (c) => { const r = await c.send({ delegation: { cnfPrivate: true } }); return sessionRefused(r) ? pass(`refused: ${describe(r)}`) : warn(`accepted: ${describe(r)}. The spec forbids the AGENT from putting private key members in cnf.jwk; it does not require a Company to refuse one. Worth refusing: it means the agent leaked a key.`); } },
  { id: 's-replay', group: 'Poppy-Session', title: 'The same Session jti twice: the second is refused', spec: '5.3', level: 'should', needs: 'session', run: async (c) => { const header = c.kit.session({ method: 'GET', url: c.probeUrl, claims: { aud: c.companyId } }); const a = await c.sendRaw(header); const b = await c.sendRaw(header); return accepted(a.res, a.body) && sessionRefused(b) ? pass('second use refused') : (!accepted(a.res, a.body) ? skip('the first use was refused, so replay cannot be judged') : warn('a reused jti was accepted (the spec says a Company MAY reject a reuse; the guide asks you to)')); } },
  { id: 's-status-400', group: 'Poppy-Session', title: 'Session failures are HTTP 400 with a JSON error, not 401 (so OAuth libraries keep a valid token)', spec: '5.3, 7', needs: 'session', run: async (c) => { const r = await c.send({ claims: { aud: 'https://other.example' } }); return r.res.status === 400 && REJECT_CODES.includes(r.body?.error) ? pass('400 invalid_session') : (sessionRefused(r) ? fail(`HTTP ${r.res.status}: use 400`) : skip('the bad Session was not refused (see its own check)')); } },
  { id: 's-ps384', group: 'Poppy-Session', title: 'A delegation signed with PS384 is accepted (Companies MUST accept ES256 and PS384)', spec: '5.2', needs: 'session', run: async (c) => { if (!c.kit.main.ps) return skip('the real agent publishes an ES256 key only'); const r = await c.send({ delegation: { alg: 'PS384' } }); return r.ok ? pass(`HTTP ${r.res.status}`) : fail(`refused: ${describe(r)}`); } },

  // ---- Sign-in, tokens, resources (needs a reference issuer this process can drive; a real issuer needs a person) ----------
  // Every refusal below is paired with a positive control for the SAME flow, and asserts WHY it was refused. A refusal for any other
  // reason (a required-PAR issuer, a malformed request) is not a pass.
  ...[
    ['o-assertion-aud', 'Client assertion aud = the token endpoint URL: refused (aud must be the issuer)', '4.1', 'must', (c) => ({ aud: `${c.issuer}/token` })],
    ['o-assertion-aud-slash', 'Client assertion aud with a trailing slash: refused (character for character)', '4.1', 'must', (c) => ({ aud: `${c.issuer}/` })],
    ['o-assertion-aud-array', 'Client assertion aud as an array: refused (a single string)', '4.1', 'must', (c) => ({ aud: [c.issuer] })],
    ['o-assertion-expired', 'An expired client assertion: refused', '4.1', 'must', () => ({ iat: Math.floor(Date.now() / 1000) - 3600 })],
    ['o-assertion-jti', 'A client assertion with no jti: refused', '4.1', 'must', () => ({ omit: ['jti'] })],
    ['o-assertion-sub', 'A client assertion whose sub is not the client_id: refused', '4.1', 'must', (c) => ({ sub: c.kit.other?.clientId ?? 'https://someone.example/client.json' })],
    ['o-assertion-forged', 'A client assertion naming the real kid but signed by another key: refused', '4.1', 'must', (c) => ({ signer: c.kit.rogue, realKid: true })],
    ['o-assertion-lifetime', 'Client assertion lasting an hour: refused (at most 5 minutes)', '4.1', 'should', () => ({ lifetime: 3600 })],
  ].map(([id, title, spec, level, make]) => ({ id, group: 'Sign-in and tokens', title, spec, level, needs: 'signin', run: async (c) => {
    const control = await c.tokenRaw({});
    if (control.body?.error !== 'invalid_grant') return skip(`control failed: a correct assertion was not accepted (${control.res.status} ${control.body?.error ?? ''})`);
    const r = await c.tokenRaw({ assertion: make(c) });
    if (r.body?.error === 'invalid_client') return pass(`refused: ${r.body.error_description ?? r.body.error}`);
    return level === 'should' ? warn(`accepted (a Company MAY reject this); answered ${r.res.status} ${r.body?.error ?? ''}`) : fail(`the assertion was accepted (HTTP ${r.res.status} ${r.body?.error ?? ''})`);
  } })),
  { id: 'o-assertion-none', group: 'Sign-in and tokens', title: 'No client assertion at all: refused (private_key_jwt is required)', spec: '4.1', needs: 'signin', run: async (c) => { const control = await c.tokenRaw({}); if (control.body?.error !== 'invalid_grant') return skip('control failed'); const r = await c.tokenRaw({ omit: true }); return r.body?.error === 'invalid_client' ? pass('refused') : fail(`accepted without an assertion: ${r.res.status} ${r.body?.error ?? ''}`); } },
  { id: 'o-assertion-replay', group: 'Sign-in and tokens', title: 'Client assertion jti reused: refused', spec: '4.1', level: 'should', needs: 'signin', run: async (c) => { const jti = `reuse-${Math.random().toString(36).slice(2)}`; const first = await c.tokenRaw({ assertion: { jti } }); if (first.body?.error !== 'invalid_grant') return skip('the first use was not accepted, so reuse cannot be judged'); const r = await c.tokenRaw({ assertion: { jti } }); return r.body?.error === 'invalid_client' ? pass('second use refused') : warn('accepted twice (a Company MAY reject a reused jti)'); } },
  { id: 'o-assertion-ps384', group: 'Sign-in and tokens', title: 'A PS384 client assertion is accepted', spec: '4.1', needs: 'signin', run: async (c) => { if (!c.kit.main.ps) return skip('the real agent has no PS384 key'); const s = await c.signIn({ assertionAlg: 'PS384' }); return s.ok ? pass('signed in with a PS384 assertion') : fail(`refused: ${s.reason}`); } },
  { id: 'o-iss-success', group: 'Sign-in and tokens', title: 'The authorization response carries iss (RFC 9207)', spec: '4.2', needs: 'signin', run: async (c) => { const s = await c.signIn({}); return !s.ok ? skip(`sign-in failed: ${s.reason}`) : (s.iss === c.issuer ? pass(`iss ${s.iss}`) : fail(`iss ${JSON.stringify(s.iss)}`)); } },
  { id: 'o-iss-error', group: 'Sign-in and tokens', title: 'An error response (access_denied) carries iss too', spec: '4.2', needs: 'signin', run: async (c) => { const s = await c.signIn({ deny: true }); return s.error === 'access_denied' ? (s.iss === c.issuer ? pass('access_denied with iss') : fail(`access_denied, iss ${JSON.stringify(s.iss)}`)) : skip(`no access_denied redirect: ${s.reason ?? ''}`); } },
  { id: 'o-pkce', group: 'Sign-in and tokens', title: 'A code redeemed with the wrong PKCE verifier: refused (invalid_grant)', spec: '4.2', needs: 'signin', run: async (c) => { const ok = await c.signIn({}); if (!ok.ok) return skip(`control failed: ${ok.reason}`); const s = await c.signIn({ wrongVerifier: true }); return s.ok ? fail('a token was issued without the right code_verifier') : (s.error === 'invalid_grant' ? pass('refused: invalid_grant') : fail(`refused for the wrong reason: ${s.reason}`)); } },
  { id: 'o-pkce-required', group: 'Sign-in and tokens', title: 'An authorization request with no code_challenge: refused (PKCE is required)', spec: '4.2', needs: 'signin', run: (c) => c.authorizeNegative({ noChallenge: true }, (s) => s.kind === 'redirect' && s.error === 'invalid_request', 'invalid_request') },
  { id: 'o-code-replay', group: 'Sign-in and tokens', title: 'An authorization code redeemed twice: the second is refused (invalid_grant)', spec: '4.2, RFC 6749 4.1.2', needs: 'signin', run: async (c) => { const s = await c.signIn({ redeemTwice: true }); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); return s.second?.error === 'invalid_grant' ? pass('second redemption refused') : fail(`second redemption answered ${s.second?.status} ${s.second?.error ?? ''}`); } },
  { id: 'o-redirect-token', group: 'Sign-in and tokens', title: 'The token request names another redirect_uri than the authorization request: refused', spec: '4.2', needs: 'signin', run: async (c) => { const ok = await c.signIn({}); if (!ok.ok) return skip(`control failed: ${ok.reason}`); const s = await c.signIn({ tokenRedirectUri: `${c.kit.redirectUri}/other` }); return s.ok ? fail('a token was issued for a different redirect_uri') : (s.error === 'invalid_grant' ? pass('refused: invalid_grant') : fail(`refused for the wrong reason: ${s.reason}`)); } },
  { id: 'o-redirect-exact', group: 'Sign-in and tokens', title: 'redirect_uri that only starts with a registered one: not accepted', spec: '4.2', needs: 'signin', run: (c) => c.authorizeNegative({ redirectSuffix: '/evil' }, (s) => s.kind === 'error' && /redirect_uri/.test(s.reason), 'a redirect_uri refusal') },
  { id: 'o-scope-subset', group: 'Sign-in and tokens', title: 'The granted scopes never exceed the requested ones (one scope asked, two asked)', spec: '4.7', needs: 'signin', run: async (c) => { for (const asked of ['orders:read', 'orders:read orders:write']) { const s = await c.signIn({ scope: asked }); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); if (s.scope === undefined) continue; // RFC 6749 5.1: the token response MAY omit scope when it is identical to the requested one
  const extra = String(s.scope).split(' ').filter((x) => x && !asked.split(' ').includes(x)); if (extra.length) return fail(`granted ${s.scope}; asked ${asked}`); } return pass('granted exactly what was asked (or the response omits scope, which RFC 6749 5.1 allows when identical), for one and for two scopes'); } },
  { id: 'o-scope-missing', group: 'Sign-in and tokens', title: 'A sign-in with no scope: invalid_scope (scope is required every time)', spec: '4.7', needs: 'signin', run: (c) => c.authorizeNegative({ scope: '' }, (s) => s.kind === 'redirect' && s.error === 'invalid_scope', 'invalid_scope') },
  { id: 'o-scope-unknown', group: 'Sign-in and tokens', title: 'A sign-in asking for an unknown scope: invalid_scope', spec: '4.7', needs: 'signin', run: (c) => c.authorizeNegative({ scope: 'orders:read nonsense:all' }, (s) => s.kind === 'redirect' && s.error === 'invalid_scope', 'invalid_scope') },
  { id: 'o-resource-unknown', group: 'Sign-in and tokens', title: 'A sign-in naming a resource the Company does not serve: invalid_target', spec: '4.5', needs: 'signin', run: (c) => c.authorizeNegative({ resource: 'https://nowhere.example' }, (s) => s.kind === 'redirect' && s.error === 'invalid_target', 'invalid_target') },
  { id: 'o-resource-token', group: 'Sign-in and tokens', title: 'A token request naming a resource the Company does not serve: invalid_target', spec: '4.5', needs: 'signin', run: async (c) => { const ok = await c.signIn({}); if (!ok.ok) return skip(`control failed: ${ok.reason}`); const s = await c.signIn({ tokenResource: 'https://nowhere.example' }); return s.ok ? fail('a token was issued for an unknown resource') : (s.error === 'invalid_target' ? pass('refused: invalid_target') : fail(`refused for the wrong reason: ${s.reason}`)); } },
  ...[
    ['o-cimd-redirect', 'Client metadata that sits behind a redirect: refused (redirects are not followed)', '/redirecting/client.json', /30\d|redirect/i, 'a redirect refusal'],
    ['o-cimd-jwks-host', 'jwks_uri on another host than the client_id: refused', '/otherhost/client.json', /jwks_uri/, 'a jwks_uri refusal'],
    ['o-cimd-mismatch', 'A document whose client_id differs from its own URL: refused', '/mismatch/client.json', /client_id/, 'a client_id refusal'],
    ['o-cimd-status', 'Client metadata answered with HTTP 404 (but a JSON body): refused (only 200 is accepted)', '/status404/client.json', /404|answered/, 'a status refusal'],
    ['o-cimd-redirect-uris', 'A client whose redirect_uris are on another domain: refused', '/redirects-in-uri/client.json', /redirect_uri/, 'a redirect_uris refusal'],
  ].map(([id, title, clientPath, re, why]) => ({ id, group: 'Sign-in and tokens', title, spec: '4.1', needs: 'signin', run: (c) => c.authorizeNegative({ clientPath, ...(clientPath.includes('redirects-in-uri') ? { redirectUri: 'https://evil.example/cb' } : {}) }, (s) => ['error', 'par'].includes(s.kind) && re.test(s.reason ?? ''), why) })),
  ...[
    ['10.0.0.5', 'a private IPv4 address'], ['169.254.169.254', 'a link-local IPv4 address'], ['[fd00::1]', 'an IPv6 unique-local address'], ['[::ffff:7f00:1]', 'an IPv4-mapped loopback'], ['127.0.0.1', 'a loopback address'],
  ].map(([host, what]) => ({ id: `o-cimd-ssrf-${host.replace(/[^0-9a-z]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '')}`, group: 'Sign-in and tokens', title: `A client_id on ${what}: refused`, spec: '3, 10', needs: 'signin', run: (c) => c.authorizeNegative({ clientUrl: `https://${host}/client.json` }, (s) => ['error', 'par'].includes(s.kind) && /loopback|private|link-local|address/i.test(s.reason ?? ''), 'an address refusal') })),
  { id: 'o-refresh', group: 'Sign-in and tokens', title: 'Refresh works and returns a new access token; a replaced refresh token should stop working', spec: '4.4', needs: 'signin', run: async (c) => { const s = await c.signIn({}); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const a = await c.refresh(s.refresh_token); if (!a.ok) return fail(`refresh refused: ${a.reason}`); if (!a.access_token) return fail('refresh returned no access token'); if (a.refresh_token && a.refresh_token !== s.refresh_token) { const old = await c.refresh(s.refresh_token); return old.ok ? warn('refreshed, but the replaced refresh token still works (RFC 6749 6 lets it; RFC 9700 asks for rotation with reuse detection)') : pass('refreshed; the replaced token is refused'); } return pass('refreshed (the same refresh token is kept, which RFC 6749 6 allows)'); } },
  { id: 'o-refresh-escalate', group: 'Sign-in and tokens', title: 'A refresh that asks for MORE scopes than were granted: invalid_scope', spec: '4.4, 4.7', needs: 'signin', run: async (c) => { const s = await c.signIn({ scope: 'orders:read' }); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const up = await c.refresh(s.refresh_token, 'orders:read account:close'); if (up.ok) return fail('a refresh granted a scope that was never granted'); if (up.error !== 'invalid_scope') return fail(`refused for the wrong reason: ${up.reason}`); const fewer = await c.refresh(s.refresh_token, 'orders:read'); return fewer.ok ? pass('refused with invalid_scope; the same refresh for fewer scopes works') : fail(`control failed: ${fewer.reason}`); } },
  { id: 'o-refresh-other-client', group: 'Sign-in and tokens', title: 'Another client presenting this refresh token: invalid_grant', spec: '4.4', needs: 'signin', run: async (c) => { if (!c.kit.other) return skip('needs a second agent identity'); const s = await c.signIn({}); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const r = await c.refresh(s.refresh_token, undefined, { other: true }); if (r.ok) return fail('another client used this refresh token'); const own = await c.refresh(s.refresh_token); return own.ok ? (r.error === 'invalid_grant' ? pass('refused: invalid_grant') : fail(`refused for the wrong reason: ${r.reason}`)) : fail(`the refusal consumed the owner's token: ${own.reason}`); } },
  { id: 'o-revoke', group: 'Sign-in and tokens', title: 'After revocation the refresh token is invalid_grant', spec: '4.6, 5.5', needs: 'signin', run: async (c) => { const s = await c.signIn({}); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const rv = await c.revoke(s.refresh_token); if (!rv.ok) return fail(`revocation refused: ${rv.reason}`); const r = await c.refresh(s.refresh_token); return r.ok ? fail('a revoked refresh token still works') : pass('refused after revocation'); } },
  { id: 'o-revoke-other-client', group: 'Sign-in and tokens', title: 'Another client cannot revoke this refresh token', spec: '4.6', needs: 'signin', run: async (c) => { if (!c.kit.other) return skip('needs a second agent identity'); const s = await c.signIn({}); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); await c.revoke(s.refresh_token, { other: true }); const r = await c.refresh(s.refresh_token); return r.ok ? pass('the owner can still refresh') : fail('another client revoked this refresh token'); } },
  { id: 'a-signed-in', group: 'Resources and tokens', title: 'A signed-in call with a matching Session succeeds', spec: '5.3, 7', needs: 'signin', run: async (c) => { const s = await c.signIn({}); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const r = await c.send({ path: c.signedInPath, accessToken: s.access_token }); return r.res.status === 200 ? pass('HTTP 200') : fail(`HTTP ${r.res.status} ${JSON.stringify(r.body)}`); } },
  ...[
    ['a-ath', 'ath of another token: refused', () => ({ claims: { ath: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' } })],
    ['a-ath-missing', 'No ath although the request carries a token: refused', () => ({ claims: { ath: undefined } })],
    ['a-ath-prefix', 'ath that only matches the first 8 characters: refused', (c, tok) => ({ claims: { ath: `${crypto.createHash('sha256').update(tok).digest('base64url').slice(0, 8)}${'A'.repeat(35)}` } })],
    ['a-iat-signed-in', 'On a signed-in call, a Session an hour old: refused', () => ({ claims: { iat: -3600 } })],
    ['a-aud-signed-in', 'On a signed-in call, a Session for another Company: refused', () => ({ claims: { aud: 'https://other.example' } })],
  ].map(([id, title, make]) => ({ id, group: 'Resources and tokens', title, spec: '5.3', needs: 'signin', run: async (c) => { const s = await c.signIn({}); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const r = await c.send({ path: c.signedInPath, accessToken: s.access_token, ...make(c, s.access_token) }); return sessionRefused(r) ? pass(`refused: ${describe(r)}`) : fail(`not refused: ${describe(r)}`); } })),
  { id: 'a-version-signed-in', group: 'Resources and tokens', title: 'On a signed-in call, no Poppy-Version: version_unsupported (HTTP 400)', spec: '3.4', needs: 'signin', run: async (c) => { const s = await c.signIn({}); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const r = await c.send({ path: c.signedInPath, accessToken: s.access_token, omitVersion: true }); return r.res.status === 400 && r.body?.error === 'version_unsupported' ? pass('400 version_unsupported') : fail(describe(r)); } },
  { id: 'a-status-signed-in', group: 'Resources and tokens', title: 'On a signed-in call, a bad Session is HTTP 400, not 401', spec: '5.3', needs: 'signin', run: async (c) => { const s = await c.signIn({}); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const r = await c.send({ path: c.signedInPath, accessToken: s.access_token, claims: { aud: 'https://other.example' } }); return r.res.status === 400 && REJECT_CODES.includes(r.body?.error) ? pass('400 invalid_session') : fail(`${describe(r)}: use 400 so OAuth libraries keep a valid token`); } },
  { id: 'a-scope', group: 'Resources and tokens', title: 'A token without orders:read is insufficient_scope (HTTP 403)', spec: '4.7, 7', needs: 'signin', run: async (c) => { const s = await c.signIn({ scope: 'orders:write' }); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const r = await c.send({ path: c.signedInPath, accessToken: s.access_token }); return r.res.status === 403 && hasScopeChallenge(r) ? pass('403 insufficient_scope') : fail(`${describe(r)}: expected 403 with insufficient_scope in WWW-Authenticate or the body`); } },
  { id: 'a-token-client', group: 'Resources and tokens', title: 'A token issued to another client than the Session iss: refused', spec: '5.3', needs: 'signin', run: async (c) => { if (!c.kit.other) return skip('needs a second agent identity'); const s = await c.signIn({}); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const r = await c.send({ path: c.signedInPath, accessToken: s.access_token, identity: c.kit.other }); return sessionRefused(r) ? pass('refused') : fail(`${describe(r)}: another agent used this token`); } },
  { id: 'a-mcp-own-token', group: 'Resources and tokens', title: 'MCP: a token for the MCP resource works there', spec: '4.5, 7', needs: 'signin', run: async (c) => { const s = await c.signIn({ resource: c.mcpUrl }); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const r = await c.send({ method: 'POST', path: '/mcp', accessToken: s.access_token }); return r.res.status === 200 ? pass('HTTP 200') : fail(`HTTP ${r.res.status} ${JSON.stringify(r.body)}`); } },
  { id: 'a-mcp-default-token', group: 'Resources and tokens', title: 'MCP: the default Company token is refused there, with a resource_metadata challenge', spec: '4.5, 7', needs: 'signin', run: async (c) => { const s = await c.signIn({}); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const r = await c.send({ method: 'POST', path: '/mcp', accessToken: s.access_token }); const ch = r.res.headers.get('www-authenticate') ?? ''; return r.res.status === 401 && /resource_metadata=/.test(ch) ? pass('401 invalid_token with resource_metadata') : fail(`HTTP ${r.res.status}; challenge ${JSON.stringify(ch)}`); } },
  { id: 'a-mcp-scope', group: 'Resources and tokens', title: 'MCP: a token without orders:read is insufficient_scope (HTTP 403)', spec: '4.7, 7', needs: 'signin', run: async (c) => { const s = await c.signIn({ scope: 'orders:write', resource: c.mcpUrl }); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const r = await c.send({ method: 'POST', path: '/mcp', accessToken: s.access_token }); return r.res.status === 403 && hasScopeChallenge(r) ? pass('403 insufficient_scope') : fail(`${describe(r)}: the MCP server did not enforce the scope`); } },
  { id: 'a-mcp-token-client', group: 'Resources and tokens', title: 'MCP: a token issued to another client than the Session iss: refused', spec: '5.3', needs: 'signin', run: async (c) => { if (!c.kit.other) return skip('needs a second agent identity'); const s = await c.signIn({ resource: c.mcpUrl }); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const r = await c.send({ method: 'POST', path: '/mcp', accessToken: s.access_token, identity: c.kit.other }); return sessionRefused(r) ? pass('refused') : fail(`${describe(r)}: another agent used this MCP token`); } },
  { id: 'a-api-mcp-token', group: 'Resources and tokens', title: 'The API refuses a token issued for the MCP resource (audience)', spec: '4.5', needs: 'signin', run: async (c) => { const s = await c.signIn({ resource: c.mcpUrl }); if (!s.ok) return skip(`sign-in failed: ${s.reason}`); const r = await c.send({ path: c.signedInPath, accessToken: s.access_token }); return r.res.status === 401 ? pass('refused: 401 invalid_token') : fail(`HTTP ${r.res.status}: a token for another resource was accepted`); } },
];

export const CHECK_LIST = CHECKS.map(({ id, group, title, spec, level, needs }) => ({ id, group, title, spec, level: level ?? 'must', needs: needs ?? null }));

/**
 * Run the suite. `target` supplies: origin, fetch, kit, probePath, and (Mock only) `driver` with the reference issuer so sign-in
 * based checks can run, plus `sessionClaimsEndpoint` (true when the probe is known to rely on Session claims, as the reference
 * catalog does). Discovery data is read once and shared.
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
  // The Session aud is the Company identifier: the issuer when there is one, else https://{domain} (spec 3.2).
  const companyId = issuer ?? origin;

  const probePath = target.probePath;
  const probeUrl = `${origin}${probePath}`;
  const send = async ({ path = probePath, method = 'GET', accessToken, omitVersion, version = SPEC_VERSION, identity, claims = {}, header = {}, noDelegation, delegation: d } = {}) => {
    const url = `${origin}${path}`;
    // Overrides that depend on the clock are written relative to now in the check list (iat: -3600 means an hour ago).
    const t = Math.floor(Date.now() / 1000);
    const cl = { aud: companyId, ...claims };
    if (typeof cl.iat === 'number' && Math.abs(cl.iat) <= 7200) cl.iat = t + cl.iat;
    const ident = identity ?? kit.main;
    let delegation;
    if (d) {
      if (d.lifetime < 0) delegation = kit.delegationJwt({ identity: ident, lifetime: 60, iat: t - 7200 }); // issued two hours ago, lasted a minute: expired
      else if (d.forged === 'rogue') delegation = kit.delegationJwt({ identity: ident, signer: kit.rogue, realKid: true });
      else if (d.forged === 'delegated') delegation = kit.delegationJwt({ identity: ident, signer: { privateKey: kit.delegated.privateKey, publicJwk: kit.delegated.publicJwk }, realKid: true });
      else if (d.issOther) delegation = kit.delegationJwt({ identity: kit.other });
      else if (d.cnfPrivate) delegation = kit.delegationJwt({ identity: ident, cnf: kit.delegated.privateJwk });
      else delegation = kit.delegationJwt({ identity: ident, lifetime: d.lifetime ?? 3600, iat: t, typ: d.typ, alg: d.alg, signer: d.rogue ? kit.rogue : null });
    }
    const session = kit.session({ method, url, accessToken, claims: cl, header, noDelegation, delegation, identity: ident });
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
  const ctx = { origin, kit, poppy, prm, as, issuer, companyId, errors, probePath, probeUrl, send, sendRaw, mcpUrl: driver?.mcpUrl, signedInPath: driver?.signedInPath ?? '/poppy/api/v1/me', sessionClaimsEndpoint: target.sessionClaimsEndpoint === true };
  if (driver) {
    Object.assign(ctx, driver.methods({ origin, kit, issuer, as, fetch: fetchImpl }));
    // A negative authorization check, with its control: the SAME request shape for the main client must reach the consent step
    // first, and the faulty one must be refused for the reason the check names, not for any other reason.
    ctx.authorizeNegative = async (variant, isRightRefusal, why) => {
      const control = await ctx.signIn({ stopAtAuthorize: true });
      if (control.kind !== 'consent') return skip(`control failed: a correct request was not accepted (${control.reason})`);
      const s = await ctx.signIn({ ...variant, stopAtAuthorize: true });
      if (s.kind === 'consent') return fail('the faulty request was accepted');
      return isRightRefusal(s) ? pass(`refused: ${s.reason ?? s.error}`)
        // RFC 9126 2.2: a pushed request is validated and its error returned at the PAR endpoint, so a refusal there with the
        // right error code is as good as one at the authorize redirect (an issuer may refuse at either step).
        : (['error', 'par', 'redirect'].includes(s.kind) && s.error === why ? pass(`refused at the ${s.kind === 'par' ? 'pushed' : 'authorization'} step: ${s.error}`) : fail(`refused, but not for the right reason (wanted ${why}): ${s.reason ?? s.error}`));
    };
  }
  // Does the probe endpoint verify Poppy-Session at all? (Spec 5.3: it may skip when it uses no Session claims.)
  let aware;
  const sessionAware = async () => (aware ??= sessionRefused(await sendRaw('not-a-jwt')));

  const results = [];
  for (const chk of CHECKS) {
    if (only && !only.includes(chk.id)) continue;
    await new Promise((res) => setImmediate(res)); // let the event loop serve other requests between checks: a run is CPU work
    let r;
    const needsProbe = chk.needs === 'probe' || chk.needs === 'session';
    const unsupported = driver?.unsupported?.(chk.id);
    const missing = unsupported ? unsupported : chk.needs === 'poppy' && !poppy ? 'poppy.json could not be read' : chk.needs === 'prm' && !prm ? 'protected resource metadata could not be read' : chk.needs === 'as' && !as ? `issuer metadata could not be read${errors.as ? ` (${errors.as})` : ''}` : needsProbe && !target.probeReady ? (target.probeReason ?? 'no probe') : chk.needs === 'signin' && !driver ? 'needs a person to sign in: use Real mode on the Run it tab, then re-run (this suite drives sign-in itself only against the reference issuer)' : null;
    if (missing) r = skip(missing);
    else if (chk.needs === 'session' && !ctx.sessionClaimsEndpoint && !(await sessionAware())) r = skip(`the probe endpoint ${probePath} does not verify Poppy-Session (see s-verifies); spec 5.3 lets it when it uses no Session claims. Choose a probe path that relies on them`);
    else {
      try { r = await chk.run(ctx); } catch (e) { r = fail(`the check crashed: ${String(e.message).slice(0, 160)}`); }
    }
    results.push({ id: chk.id, group: chk.group, title: chk.title, spec: chk.spec, level: chk.level ?? 'must', ...r });
  }
  // A negative Session check is meaningful only if the correct Session was accepted. Otherwise say so instead of passing by accident.
  const valid = results.find((r) => r.id === 's-valid');
  if (valid && valid.status !== 'pass') for (const r of results) if (r.group === 'Poppy-Session' && !['s-valid', 's-verifies'].includes(r.id) && r.status !== 'skip') { r.detail = `inconclusive: a correct Session was not accepted, so this result proves nothing (${r.detail})`; r.status = 'skip'; }
  const count = (s) => results.filter((r) => r.status === s).length;
  // conformant = no check failed; complete = every check ran. A report with skips is NOT a full pass.
  return { spec: `Personal Agent Protocol ${SPEC_VERSION}`, specUrl: SPEC, origin, issuer: issuer ?? null, results, summary: { pass: count('pass'), fail: count('fail'), warn: count('warn'), skip: count('skip'), total: results.length }, conformant: count('fail') === 0, complete: count('skip') === 0 };
}
