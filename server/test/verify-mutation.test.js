// Mutation test of the SUITE: each mutant is a subtle way a Company or issuer could be wrong (not one of the named defects). The
// reference source is copied to a temp directory, patched, and the whole suite is run against it. A mutant the suite passes is a
// broken Company the suite would certify, so every mutant here must make `conformant` false and trip the named check.
// Origin: an independent review (2026-11-16) found 37 of 46 such mutants were missed by the first suite; these are those.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src');
const ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'pvl-mut-'));
after(() => fs.rmSync(ROOT, { recursive: true, force: true }));
const C = 'reference/company.js'; const I = 'reference/issuer.js'; const R = 'reference/clientResolver.js'; const M = 'reference/common.js';

const MUTANTS = [
  ['htu is a prefix match', C, 'c.htu !== htu)', '!htu.startsWith(c.htu))', ['s-htu-truncated']],
  ['htu compared on origin only', C, 'c.htu !== htu)', 'new URL(String(c.htu)).origin !== COMPANY_ORIGIN)', ['s-htu']],
  ['htu compared on path only (host ignored)', C, 'c.htu !== htu)', 'new URL(String(c.htu)).pathname !== new URL(htu).pathname)', ['s-htu-host']],
  ['htu compared case-insensitively (the path is case-sensitive)', C, 'c.htu !== htu)', 'String(c.htu).toLowerCase() !== htu.toLowerCase())', ['s-htu-case']],
  ['aud accepted as an array holding the Company', C, 'c.aud !== ISSUER)', '![].concat(c.aud).includes(ISSUER))', ['s-aud-array']],
  ['aud accepted with a trailing slash', C, 'c.aud !== ISSUER)', "c.aud !== ISSUER && c.aud !== ISSUER + '/')", ['s-aud-slash']],
  ['iat window of one day', C, 'IAT_WINDOW = 60;', 'IAT_WINDOW = 86400;', ['s-iat-old']],
  ['iat window skipped when a token is present', C, "if (!has('no_iat_window') &&", "if (!has('no_iat_window') && !accessToken &&", ['a-iat-signed-in']],
  ['a missing ath is accepted when a token is present', C, 'if (c.ath !== ath) throw', 'if (c.ath !== undefined && c.ath !== ath) throw', ['a-ath-missing']],
  ['ath compared on 8 characters only', C, 'if (c.ath !== ath) throw', 'if (String(c.ath).slice(0,8) !== ath.slice(0,8)) throw', ['a-ath-prefix']],
  ['a delegation self-signed by cnf.jwk is accepted', C, '!signer || !verifyJws(d, signer)', '!signer || !(verifyJws(d, signer) || verifyJws(d, jwk))', ['s-delegation-selfsigned']],
  ['the delegation signature is never verified (only the kid exists)', C, '!signer || !verifyJws(d, signer)', '!signer', ['s-delegation-forged']],
  ['delegation iss is not compared with the Session iss', C, 'if (d.payload.iss !== s.payload.iss) throw', 'if (false) throw', ['s-delegation-iss']],
  ['Session kid is not compared with the delegated key thumbprint', C, 'if (s.header.kid !== thumbprint(jwk)) throw', 'if (false) throw', ['s-kid']],
  ['delegations may last 72 hours', C, 'MAX_DELEGATION = 24 * 3600', 'MAX_DELEGATION = 72 * 3600', ['s-delegation-24h']],
  ['a Session after the delegation expired is accepted', C, ["if (d.payload.exp < t) throw bad('the delegation has expired');", "if (c.iat > delegationExp) throw bad('the Session was signed after the delegation expired');"], ['', ''], ['s-delegation-expired']],
  ['a bad Session on a signed-in call answers 401', C, "jsonResponse(has('session_401') && error === 'invalid_session' ? 401 : status", "jsonResponse((has('session_401') || accessToken) && error === 'invalid_session' ? 401 : status", ['a-status-signed-in']],
  ['Poppy-Version not checked on signed-in calls', C, "if (!has('no_version_check') &&", "if (!has('no_version_check') && !accessToken &&", ['a-version-signed-in']],
  ['the MCP server does not enforce the scope', C, "resourceId: MCP_URL, requiredScope: 'orders:read'", 'resourceId: MCP_URL', ['a-mcp-scope']],
  ['token/Session client mismatch ignored on MCP', C, 'if (who && who.clientId !== claims.client_id &&', 'if (who && resourceId !== MCP_URL && who.clientId !== claims.client_id &&', ['a-mcp-token-client']],
  ['scope check by family prefix (orders:*)', C, "!String(claims.scope).split(' ').includes(requiredScope)", "!String(claims.scope).split(' ').some((x) => x.split(':')[0] === requiredScope.split(':')[0])", ['a-scope']],
  ['cnf.jwk with private members is accepted', C, '|| PRIVATE_MEMBERS.some((m) => m in jwk)', '', ['s-delegation-cnf-private'], 'warn'],
  ['the Session is only verified when there is no token', C, 'who = await verifySession(', 'who = accessToken ? null : await verifySession(', ['a-ath']],
  ['client assertion aud accepted with a trailing slash', I, 'a.payload.aud === ISSUER ||', "a.payload.aud === ISSUER || a.payload.aud === ISSUER + '/' ||", ['o-assertion-aud-slash']],
  ['client assertion aud accepted as an array', I, 'a.payload.aud === ISSUER ||', '[].concat(a.payload.aud).includes(ISSUER) ||', ['o-assertion-aud-array']],
  ['authorization code can be redeemed twice', I, 'codes.delete(form.code);', '', ['o-code-replay']],
  ['refresh may ask for MORE scopes', I, "if (asked.some((s) => !r.scopes.includes(s))) throw new OAuthError('invalid_scope', 'a refresh may ask for fewer scopes, never more');", '', ['o-refresh-escalate']],
  ['the token endpoint ignores a redirect_uri mismatch', I, 'if (c.redirectUri !== form.redirect_uri) throw', 'if (false) throw', ['o-redirect-token']],
  ['PKCE optional when no challenge was sent', I, ["if (!has('no_pkce') && (!p.code_challenge || p.code_challenge_method !== 'S256')) return", "if (!has('no_pkce')) {\n        const chal"], ['if (false) return', "if (!has('no_pkce') && c.challenge) {\n        const chal"], ['o-pkce-required']],
  ['any authenticated client can revoke', I, 'if (r && r.clientId === client.clientId) r.revoked = true;', 'if (r) r.revoked = true;', ['o-revoke-other-client']],
  ['another client can use the refresh token', I, 'r.clientId !== client.clientId || ', '', ['o-refresh-other-client']],
  ['an expired client assertion is accepted', I, 'if (a.payload.exp <= t - 60 || a.payload.iat > t + 60) throw', 'if (false) throw', ['o-assertion-expired']],
  ['redirect_uris of the client document are not checked against its domain', R, "if (!(loopback || (ru.protocol === 'https:' && ru.host === u.host))) throw", 'if (false) throw', ['o-cimd-redirect-uris']],
  ['client metadata status is not checked', R, 'if (res.status !== 200) throw', 'if (false) throw', ['o-cimd-status']],
  ['only 127.x is treated as a blocked address', M, 'const v4 = (a, b) => a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);', 'const v4 = (a) => a === 127;', ['o-cimd-ssrf-10-0-0-5', 'o-cimd-ssrf-169-254-169-254']],
  ['IPv6 unique-local and link-local are not blocked', M, 'return (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80;', 'return false;', ['o-cimd-ssrf-fd00-1']],
  ['IPv4-mapped IPv6 is not blocked', M, "const mapped = /^::ffff:", "const mapped = /^::NEVER:", ['o-cimd-ssrf-ffff-7f00-1']],
  ['no address is blocked at all', M, "if (h === 'localhost' || h.endsWith('.localhost')) return true;", 'return false;', ['o-cimd-ssrf-127-0-0-1']],
  ['scope escalation only when two scopes are asked', I, "if (has('grant_extra_scopes')) scopes = [...scopes, 'account:close'];", "if (scopes.length > 1) scopes = [...scopes, 'account:close'];", ['o-scope-subset']],
  ['the client assertion signature is not verified', I, 'if (!candidates.some((k) => verifyJws(a, k))) throw', 'if (false) throw', ['o-assertion-forged']],
  ['the client assertion sub need not equal iss', I, 'a.payload.sub !== clientId || (form.client_id && form.client_id !== clientId)', '(form.client_id && form.client_id !== clientId)', ['o-assertion-sub']],
  ['a client assertion without jti is accepted', I, "if (typeof a.payload.jti !== 'string' || !a.payload.jti) throw", 'if (false) throw', ['o-assertion-jti']],
  ['a sign-in with no scope is accepted', I, "if (!scopes.length) return back('invalid_scope', 'scope is required on every sign-in');", "if (!scopes.length) scopes.push('orders:read');", ['o-scope-missing']],
  ['unknown scopes are ignored', I, "if (scopes.some((s) => !SCOPES[s])) return back('invalid_scope', 'a requested scope is unknown');", "scopes.splice(0, scopes.length, ...scopes.filter((s) => SCOPES[s])); if (!scopes.length) return back('invalid_scope', 'x');", ['o-scope-unknown']],
  ['the token endpoint accepts an unknown resource', I, "if (form.resource && !KNOWN_RESOURCES.has(form.resource)) throw new OAuthError('invalid_target', 'unknown resource');", '', ['o-resource-token']],
  ['token_endpoint is missing from the metadata', I, '      token_endpoint: `${ISSUER}/token`,\n', '', ['as-token-endpoint']],
  ['iss is left off the deny redirect', I, "return { url: redirectWith(a.params.redirect_uri, { error: 'access_denied', error_description: 'the user declined', state: a.params.state }, { isError: true }) };", "{ const u = new URL(a.params.redirect_uri); u.searchParams.set('error','access_denied'); u.searchParams.set('state', a.params.state); return { url: u.href }; }", ['o-iss-error']],
];

let n = 0;
for (const [name, file, from, to, expect, kind] of MUTANTS) {
  test(`mutant: ${name}`, async () => {
    const dir = path.join(ROOT, `m${n++}`);
    fs.cpSync(SRC, path.join(dir, 'src'), { recursive: true });
    const f = path.join(dir, 'src', file);
    let text = fs.readFileSync(f, 'utf8');
    const froms = [].concat(from); const tos = [].concat(to);
    froms.forEach((fr, i) => { assert.ok(text.includes(fr), `the patch did not apply: ${fr.slice(0, 60)}`); text = text.replace(fr, () => tos[i]); });
    fs.writeFileSync(f, text);
    const q = (p) => import(pathToFileURL(path.join(dir, 'src', p)).href);
    const { createReference } = await q('reference/index.js');
    const { createAgentKit } = await q('verify/agentKit.js');
    const { createReferenceDriver } = await q('verify/driver.js');
    const { runSuite } = await q('verify/suite.js');
    const kit = createAgentKit();
    const ref = createReference({ hosts: kit.hosts() });
    const r = await runSuite({ origin: 'https://company.example', fetch: ref.fetch, kit, probePath: '/poppy/api/v1/catalog', probeReady: true, sessionClaimsEndpoint: true, driver: createReferenceDriver(ref) });
    const bad = r.results.filter((x) => x.status === 'fail').map((x) => x.id);
    if (kind === 'warn') {
      // a SHOULD-level rule: the mutant is reported, but it is not a conformance failure
      for (const id of expect) assert.equal(r.results.find((x) => x.id === id).status, 'warn', `${id} should warn`);
      assert.equal(r.conformant, true, 'a SHOULD-level mutant is not a failure');
      return;
    }
    assert.equal(r.conformant, false, 'the suite passed a broken Company');
    for (const id of expect) assert.ok(bad.includes(id), `${id} did not fail; failing: ${bad.join(', ')}`);
  });
}
