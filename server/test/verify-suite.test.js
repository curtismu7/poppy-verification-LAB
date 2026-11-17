import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createReference, DEFECTS } from '../src/reference/index.js';
import { createAgentKit } from '../src/verify/agentKit.js';
import { createReferenceDriver } from '../src/verify/driver.js';
import { runSuite } from '../src/verify/suite.js';

async function suiteFor(defects = []) {
  const kit = createAgentKit();
  const ref = createReference({ defects, hosts: kit.hosts() });
  return runSuite({ origin: 'https://company.example', fetch: ref.fetch, kit, probePath: '/poppy/api/v1/catalog', probeReady: true, driver: createReferenceDriver(ref) });
}
const failing = (r) => r.results.filter((x) => x.status === 'fail').map((x) => x.id);

test('the clean reference passes every check', async () => {
  const r = await suiteFor();
  assert.deepEqual(failing(r), [], JSON.stringify(r.results.filter((x) => x.status !== 'pass').map((x) => [x.id, x.status, x.detail])));
  assert.equal(r.summary.warn + r.summary.skip, 0, JSON.stringify(r.results.filter((x) => x.status !== 'pass')));
  assert.ok(r.summary.total >= 55, `${r.summary.total} checks`);
});

// Every defect trips EXACTLY these checks (f = fail, w = warn). The sets are pinned, so a defect that starts tripping an unrelated
// check, or stops tripping its own, fails here. A SHOULD-level check warns instead of failing.
const SETS = {
  no_protected_resources: 'as-protected-resources:f', no_revocation_endpoint: 'as-revocation:f', assertion_aud_token_endpoint: 'o-assertion-aud:f',
  assertion_long_lifetime: 'o-assertion-lifetime:w', grant_extra_scopes: 'o-scope-subset:f o-refresh-escalate:f', no_iss_param: 'o-iss-success:f o-iss-error:f',
  iss_missing_on_error: 'o-iss-error:f', no_pkce: 'o-pkce:f o-pkce-required:f', loose_redirect_uri: 'o-redirect-exact:f', follow_redirects: 'o-cimd-redirect:f',
  jwks_other_host: 'o-cimd-jwks-host:f', no_version_check: 's-version-missing:f s-version-major:f a-version-signed-in:f', session_401: 's-status-400:f a-status-signed-in:f',
  no_replay_check: 's-replay:w', no_aud_check: 's-aud:f s-aud-slash:f s-aud-array:f s-status-400:s a-aud-signed-in:f a-status-signed-in:f',
  no_htu_check: 's-htu:f s-htu-suffix:f s-htu-truncated:f s-htu-host:f s-htu-case:f', no_htm_check: 's-htm:f', no_iat_window: 's-iat-old:f s-iat-future:f a-iat-signed-in:f',
  skip_ath: 'a-ath:f a-ath-missing:f a-ath-prefix:f', accept_no_delegation: 's-no-delegation:f', long_delegation_ok: 's-delegation-24h:f',
  accept_any_typ: 's-typ-session:f s-delegation-typ:f', accept_weak_alg: 's-alg-none:f s-alg-hs256:f', token_client_mismatch_ok: 'a-token-client:f a-mcp-token-client:f',
  mcp_accepts_default_token: 'a-mcp-default-token:f', no_audience_check: 'a-mcp-default-token:f a-api-mcp-token:f', scope_not_enforced: 'a-scope:f a-mcp-scope:f',
  refresh_not_rotated_revoked_ok: 'o-refresh:w o-revoke:f',
};
const letter = { fail: 'f', warn: 'w', skip: 's' };
for (const [defect, expected] of Object.entries(SETS)) {
  test(`defect ${defect} trips exactly: ${expected}`, async () => {
    const r = await suiteFor([defect]);
    const got = r.results.filter((x) => x.status !== 'pass').map((x) => `${x.id}:${letter[x.status]}`).sort();
    assert.deepEqual(got, expected.split(' ').sort());
  });
}
test('every defect has a pinned set, so none is left untested', () => {
  assert.deepEqual(Object.keys(DEFECTS).filter((d) => !(d in SETS)), []);
});
test('a PAR-required issuer does not turn the CIMD refusals into accidental passes', async () => {
  // The review found that with require_pushed_authorization_requests every variant client was refused for skipping the push, so the
  // CIMD checks passed whatever the issuer did. Each negative now has a control and names the reason it expects.
  const run = async (defects) => {
    const kit = createAgentKit();
    const ref = createReference({ defects, hosts: kit.hosts(), parRequired: true });
    return runSuite({ origin: 'https://company.example', fetch: ref.fetch, kit, probePath: '/poppy/api/v1/catalog', probeReady: true, sessionClaimsEndpoint: true, driver: createReferenceDriver(ref) });
  };
  assert.deepEqual(failing(await run([])), []);
  const bad = failing(await run(['follow_redirects', 'jwks_other_host']));
  assert.deepEqual(bad.sort(), ['o-cimd-jwks-host', 'o-cimd-redirect']);
});

// ---- the suite against Companies that are not the reference: it must not pass garbage and must not fail what the spec allows ----
const rawSuite = (fetch, extra = {}) => runSuite({ origin: 'https://company.example', fetch, kit: createAgentKit(), probePath: '/poppy/api/v1/me', probeReady: true, ...extra });
const answer = (status, body, type = 'application/json') => new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers: { 'content-type': type } });
const byId = (r) => Object.fromEntries(r.results.map((x) => [x.id, x]));

for (const [name, make] of [['404 for everything', () => answer(404, { error: 'not_found' })], ['500 for everything', () => answer(500, { error: 'boom' })], ['an HTML 200 for everything', () => answer(200, '<html></html>', 'text/html')], ['400 invalid_request for everything', () => answer(400, { error: 'invalid_request' })]]) {
  test(`a Company that answers ${name}: nothing passes by accident`, async () => {
    const r = await rawSuite(async () => make());
    const b = byId(r);
    assert.equal(r.conformant, false);
    assert.notEqual(b['s-valid'].status, 'pass', `s-valid: ${b['s-valid'].detail}`);
    assert.equal(b['disc-poppy-json'].status, 'fail');
    // no Session check may claim a pass or a fail: they are inconclusive without a working probe
    for (const x of r.results.filter((y) => y.group === 'Poppy-Session' && !['s-valid', 's-verifies'].includes(y.id))) assert.equal(x.status, 'skip', `${x.id}: ${x.status} ${x.detail}`);
  });
}
test('a network failure is a failed s-valid, never a pass', async () => {
  const r = await rawSuite(async () => { throw new TypeError('fetch failed'); });
  assert.equal(byId(r)['s-valid'].status, 'fail');
  assert.match(byId(r)['s-valid'].detail, /fetch failed/);
});
test('an endpoint that answers 401 before it looks at Poppy-Session is not failed for it (spec 5.3 SHOULD)', async () => {
  const kit = createAgentKit();
  const ref = createReference({ hosts: kit.hosts() });
  const fetch = async (url, init) => (new URL(url).pathname === '/poppy/api/v1/me' ? answer(401, { error: 'invalid_token' }) : ref.fetch(url, init));
  const r = await runSuite({ origin: 'https://company.example', fetch, kit, probePath: '/poppy/api/v1/me', probeReady: true });
  const b = byId(r);
  assert.equal(b['s-valid'].status, 'pass');
  assert.equal(b['s-verifies'].status, 'warn');
  assert.match(b['s-verifies'].detail, /does not verify Poppy-Session/);
  assert.equal(r.results.filter((x) => x.group === 'Poppy-Session' && x.status === 'fail').length, 0, JSON.stringify(r.results.filter((x) => x.group === 'Poppy-Session' && x.status === 'fail')));
  assert.equal(b['s-aud'].status, 'skip');
  assert.equal(r.complete, false);
});
test('a signed-out-only Company (no protected resource metadata, no auth) is valid (spec 3.2)', async () => {
  const doc = { protocol_version: '1.0', organization: { name: 'X', domain: 'company.example' }, apis: [{ type: 'openapi', url: 'https://company.example/openapi.json', description: 'x' }] };
  const r = await rawSuite(async (url) => (url.endsWith('/poppy.json') ? answer(200, doc) : answer(404, { error: 'not_found' })));
  const b = byId(r);
  assert.equal(b['prm-resource'].status, 'pass');
  assert.equal(b['disc-issuer'].status, 'skip');
  assert.equal(b['disc-poppy-json'].status, 'pass');
});
test('the verdict says when checks were skipped: conformant is "no failure", complete is "every check ran"', async () => {
  const r = await rawSuite(async () => answer(404, {}));
  assert.equal(typeof r.complete, 'boolean');
  const clean = await suiteFor();
  assert.equal(clean.conformant, true);
  assert.equal(clean.complete, true);
});
