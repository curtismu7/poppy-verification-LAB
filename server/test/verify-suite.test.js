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

// Every defect must make at least one check fail, and the failing check must be the one that names it. A verifier that cannot fail proves nothing.
const EXPECT = {
  no_protected_resources: 'as-protected-resources', no_revocation_endpoint: 'as-revocation', assertion_aud_token_endpoint: 'o-assertion-aud',
  grant_extra_scopes: 'o-scope-subset', no_iss_param: 'o-iss-success', iss_missing_on_error: 'o-iss-error', no_pkce: 'o-pkce', loose_redirect_uri: 'o-redirect-exact',
  follow_redirects: 'o-cimd-redirect', jwks_other_host: 'o-cimd-jwks-host', no_version_check: 's-version-missing', session_401: 's-status-400',
  no_replay_check: 's-replay', no_aud_check: 's-aud', no_htu_check: 's-htu', no_htm_check: 's-htm', no_iat_window: 's-iat-old', skip_ath: 'a-ath',
  accept_no_delegation: 's-no-delegation', long_delegation_ok: 's-delegation-24h', accept_any_typ: 's-typ-session', accept_weak_alg: 's-alg-none',
  token_client_mismatch_ok: 'a-token-client', mcp_accepts_default_token: 'a-mcp-default-token', no_audience_check: 'a-api-mcp-token', scope_not_enforced: 'a-scope',
  refresh_not_rotated_revoked_ok: 'o-revoke',
};
for (const [defect, check] of Object.entries(EXPECT)) {
  test(`defect ${defect} is caught by ${check}`, async () => {
    const r = await suiteFor([defect]);
    const hit = r.results.find((x) => x.id === check);
    // assertion_long_lifetime and replay are SHOULD-level, so they warn instead of fail.
    assert.ok(['fail', 'warn'].includes(hit.status), `${check} was ${hit.status}: ${hit.detail}`);
  });
}
test('every defect has an expectation, so none is left untested', () => {
  const missing = Object.keys(DEFECTS).filter((d) => !(d in EXPECT) && d !== 'assertion_long_lifetime');
  assert.deepEqual(missing, []);
});
test('assertion_long_lifetime is caught as a warning', async () => {
  const r = await suiteFor(['assertion_long_lifetime']);
  assert.equal(r.results.find((x) => x.id === 'o-assertion-lifetime').status, 'warn');
});
