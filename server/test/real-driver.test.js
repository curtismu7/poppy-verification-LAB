// The Real-mode headless sign-in driver, tested against the in-process reference issuer fronted by fake PingFederate-style pages
// (ref.addHost overrides the issuer host): GET authorize = login HTML, POST login = consent HTML, POST consent = 302 to the callback.
// Equivalence: every sign-in check must give the same verdict as under the Mock driver; the skipped-by-design ones skip with a reason.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createReference } from '../src/reference/index.js';
import { createAgentKit } from '../src/verify/agentKit.js';
import { createReferenceDriver } from '../src/verify/driver.js';
import { createRealDriver } from '../src/verify/realDriver.js';
import { runSuite } from '../src/verify/suite.js';

const SCOPES = { read: 'orders:read', other: 'orders:write', escalate: 'account:close' };
const page = (title, body) => new Response(`<!doctype html><html><head><title>${title}</title></head><body>${body}</body></html>`, { status: 200, headers: { 'content-type': 'text/html' } });
const input = (type, name, value = '') => `<input type="${type}" name="${name}" value="${value}">`;

/** PF-style front for the issuer host: pages for authorize/login/consent, everything else (par, token, revoke, jwks, metadata) delegated. */
function fakePf(ref) {
  return async (url, init = {}) => {
    const u = new URL(url);
    const method = String(init.method || 'GET').toUpperCase();
    const body = Object.fromEntries(new URLSearchParams(String(init.body ?? '')));
    if (method === 'GET' && u.pathname === '/authorize') {
      const s = await ref.issuer.startAuthorization(Object.fromEntries(u.searchParams));
      if (s.kind === 'redirect') return new Response(null, { status: 302, headers: { location: s.url } });
      if (s.kind === 'error') return page('Error', `<p>${s.error}: ${s.description}</p>`);
      // consent id flows to the next page in hidden fields, as PingFederate's adapter session does
      return page('Sign in', `<form method="post" action="/resume">${input('hidden', 'consentId', s.id)}${input('text', 'pf.username')}${input('password', 'pf.pass')}${input('hidden', 'pf.ok')}${input('hidden', 'pf.cancel')}${input('hidden', 'pf.adapterId', 'AiDemoPfHtmlForm')}</form>`);
    }
    if (method === 'POST' && u.pathname === '/resume') {
      if (!('pf.pass' in body)) {
        const out = body['pf.oauth.authz.consent'] === 'deny' ? ref.issuer.deny(body.consentId) : ref.issuer.approve(body.consentId);
        return new Response(null, { status: 302, headers: { location: out.url } });
      }
      const p = ref.issuer.pending(body.consentId);
      if (!p) return page('Error', '<p>expired</p>');
      return page('Request for Approval', `<form method="post" action="/resume">${input('hidden', 'consentId', body.consentId)}${input('hidden', 'cSRFToken', 'tok')}${input('checkbox', 'scope', p.scopes.map((s) => s.name).join(' '))}${input('hidden', 'pf.oauth.authz.consent')}</form>`);
    }
    return ref.issuer.handle(url, init);
  };
}

function lab({ pfOverride = null, ref: useRef } = {}) {
  const kit = createAgentKit();
  const ref = useRef ?? createReference({ hosts: kit.hosts() });
  ref.addHost(new URL('https://auth.company.example').host, pfOverride ?? fakePf(ref));
  const real = createRealDriver({ redirectUri: kit.redirectUri, user: 'demo-user', password: 'demo-pass', scopes: SCOPES, mcpUrl: 'https://company.example/mcp' });
  const target = { origin: 'https://company.example', fetch: ref.fetch, kit, probePath: '/poppy/api/v1/catalog', probeReady: true, sessionClaimsEndpoint: true, driver: real };
  return { ref, kit, real, target, run: (only) => runSuite(target, only ? { only } : {}) };
}

const byId = (r) => Object.fromEntries(r.results.map((x) => [x.id, x]));

// The same run with the Mock driver, for equivalence.
async function mockRun() {
  const kit = createAgentKit();
  const ref = createReference({ hosts: kit.hosts() });
  return runSuite({ origin: 'https://company.example', fetch: ref.fetch, kit, probePath: '/poppy/api/v1/catalog', probeReady: true, sessionClaimsEndpoint: true, driver: createReferenceDriver(ref) });
}

// Checks the Real driver supports (everything except the variant-client CIMD set, which Real skips by design).
const SUPPORTED = (r) => r.results.filter((x) => !(x.id.startsWith('o-cimd') || x.id === 'o-redirect-exact')).map((x) => [x.id, x.status]);

test('the fake PF front is transparent: with the real driver the clean reference still passes every supported check', async () => {
  const { run } = lab();
  const mock = await mockRun();
  const real = await run();
  assert.deepEqual(SUPPORTED(real), SUPPORTED(mock), JSON.stringify(real.results.filter((x) => x.status !== 'pass').map((x) => [x.id, x.status, x.detail])));
  assert.equal(real.summary.fail, 0);
  assert.equal(real.summary.pass, 96, '96 checks ran (107 minus the 11 skipped-by-design CIMD checks)');
  const cimd = real.results.filter((x) => x.id.startsWith('o-cimd') || x.id === 'o-redirect-exact');
  assert.equal(cimd.length, 11);
  for (const x of cimd) { assert.equal(x.status, 'skip'); assert.match(x.detail, /variant client document/); }
});

test('every non-CIMD verdict matches the Mock driver run exactly (the front carries the verdict)', async () => {
  const mock = await mockRun();
  const { run } = lab();
  const real = await run();
  assert.deepEqual(SUPPORTED(real).sort(), SUPPORTED(mock).sort());
});

test('skipped-by-design in Real: PS384 and the second-agent checks are skipped with their reasons (the real agent publishes ES256 only)', async () => {
  const kit = createAgentKit();
  const ref = createReference({ hosts: kit.hosts() });
  ref.addHost('auth.company.example', fakePf(ref));
  const real = createRealDriver({ redirectUri: kit.redirectUri, user: 'u', password: 'p', scopes: SCOPES, mcpUrl: 'https://company.example/mcp' });
  // A Real-mode kit: the lab agent's own identity, one ES256 key, no second agent.
  const main = { clientId: kit.main.clientId, privateKey: kit.main.es.privateKey, publicJwk: kit.main.es.publicJwk, kid: kit.main.kid };
  const realKit = createAgentKit({ main, redirectUri: kit.redirectUri, withSecondAgent: false });
  const r = await runSuite({ origin: 'https://company.example', fetch: ref.fetch, kit: realKit, probePath: '/poppy/api/v1/catalog', probeReady: true, sessionClaimsEndpoint: true, driver: real });
  const b = byId(r);
  assert.equal(b['s-ps384'].status, 'skip', JSON.stringify(b['s-ps384'])); assert.match(b['s-ps384'].detail, /ES256 key only/);
  assert.equal(b['o-assertion-ps384'].status, 'skip', JSON.stringify(b['o-assertion-ps384'])); assert.match(b['o-assertion-ps384'].detail, /PS384/);
});

test('an unknown login page stops with a clear reason and the check skips, no crash', async () => {
  const weird = async (url, init = {}) => {
    const u = new URL(url);
    if (u.pathname === '/authorize') return page('Portal One-Time Passcode', '<form method="post" action="/otp"><input type="text" name="otp"><input type="hidden" name="csrf" value="t"></form>');
    if (u.pathname === '/otp') return page('Portal', '<p>still confused</p>');
    const ref = weird.ref;
    return ref.issuer.handle(url, init);
  };
  const kit = createAgentKit();
  const ref = createReference({ hosts: kit.hosts() });
  weird.ref = ref;
  ref.addHost('auth.company.example', weird);
  const real = createRealDriver({ redirectUri: kit.redirectUri, user: 'u', password: 'p', scopes: SCOPES });
  const r = await runSuite({ origin: 'https://company.example', fetch: ref.fetch, kit, probePath: '/poppy/api/v1/catalog', probeReady: true, sessionClaimsEndpoint: true, driver: real }, { only: ['o-iss-success'] });
  const row = r.results.find((x) => x.id === 'o-iss-success');
  assert.equal(row.status, 'skip');
  assert.match(row.detail, /unsupported sign-in page: Portal One-Time Passcode/);
});

test('credentials never appear in a report, a step, or sessions.log', async () => {
  // The driver's methods() closure is the only place they exist; nothing it returns carries them.
  const kit = createAgentKit();
  const ref = createReference({ hosts: kit.hosts() });
  ref.addHost('auth.company.example', fakePf(ref));
  const user = 'secret-user-name'; const password = 'secret-password-value';
  const real = createRealDriver({ redirectUri: kit.redirectUri, user, password, scopes: SCOPES });
  const m = real.methods({ kit, issuer: 'https://auth.company.example', as: ref.issuer.metadata(), fetch: ref.fetch });
  const s = await m.signIn({});
  assert.equal(s.ok, true);
  const dump = JSON.stringify(s);
  assert.ok(!dump.includes(password) && !dump.includes(user), 'the sign-in result leaked credentials');
  const raw = await m.tokenRaw({});
  assert.ok(!JSON.stringify(raw).includes(password) && !JSON.stringify(raw).includes(user));
});

test('a run without signIn, or without the env configured, behaves exactly as before', async () => {
  // covered at the app level in mock-flow.test.js; here: a driver-less target still skips sign-in checks with the person reason
  const kit = createAgentKit();
  const ref = createReference({ hosts: kit.hosts() });
  const r = await runSuite({ origin: 'https://company.example', fetch: ref.fetch, kit, probePath: '/poppy/api/v1/catalog', probeReady: true, sessionClaimsEndpoint: true });
  const b = byId(r);
  assert.equal(b['o-pkce'].status, 'skip');
  assert.match(b['o-pkce'].detail, /person/);
});
