import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { createApp } from '../src/app.js';
import { createSessions } from '../src/sessions.js';
import { createHealth } from '../src/health.js';
import { generateEs256Key, jwkThumbprint, decodeJws } from '../src/jose.js';
import { clientMetadata, jwksDocument } from '../src/agent.js';
import { createReference } from '../src/reference/index.js';
import { jsonResponse } from '../src/reference/common.js';

const opened = [];
after(() => { for (const s of opened) s.close(); });
const freePort = () => new Promise((res) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); });
const health = () => createHealth({ runChecks: async () => [], intervalMs: 3_600_000 });

async function mockApp() {
  const port = await freePort();
  const app = createApp({ agent: null, hosted: true, baseUrl: '', sessions: createSessions(), health: health(), localOrigin: `http://127.0.0.1:${port}`, fetchImpl: () => { throw new Error('Mock must not use the network'); } });
  const server = await new Promise((res) => { const s = http.createServer(app).listen(port, '127.0.0.1', () => res(s)); });
  opened.push(server);
  const base = `http://127.0.0.1:${port}`;
  const call = (path, body, ws = 'm1') => fetch(`${base}${path}`, { method: body === undefined ? 'GET' : 'POST', headers: { 'content-type': 'application/json', 'x-workspace': ws }, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' });
  return { base, call };
}

async function signIn(a, { ws = 'm1', scope = 'orders:read', action = 'approve', resource } = {}) {
  const d = await (await a.call('/api/discover', { origin: 'https://company.example', issuer: 'https://auth.company.example' }, ws)).json();
  assert.equal(d.ok, true, JSON.stringify(d.checks?.filter((c) => !c.ok)));
  const au = await a.call('/api/authorize', { scope, resource }, ws);
  const auj = await au.json();
  assert.equal(au.status, 200, JSON.stringify(auj));
  const id = new URL(auj.url, a.base).searchParams.get('consent');
  const consent = await (await a.call(`/api/mock/consent?id=${encodeURIComponent(id)}`, undefined, ws)).json();
  const done = await (await a.call('/api/mock/consent', { id, action }, ws)).json();
  const cb = await fetch(done.redirect, { redirect: 'manual', headers: { 'x-workspace': ws } });
  return { d, auj, consent, redirect: new URL(done.redirect), cb };
}

test('Mock end to end: discover, PAR, consent screen, redirect with iss, token, signed call', async () => {
  const a = await mockApp();
  const r = await signIn(a);
  assert.equal(r.auj.par, true, 'the reference issuer lists a PAR endpoint, so the agent pushed the request');
  assert.equal(r.consent.company, 'company.example');
  assert.deepEqual(r.consent.scopes.map((s) => s.name), ['orders:read']);
  assert.equal(r.redirect.searchParams.get('iss'), 'https://auth.company.example', 'RFC 9207');
  assert.match(r.cb.headers.get('location'), /signin=ok/);
  const st = await (await a.call('/api/state')).json();
  assert.equal(st.signedIn, true);
  const c = await (await a.call('/api/call', { path: '/poppy/api/v1/me' })).json();
  assert.equal(c.response.status, 200, JSON.stringify(c.response));
  assert.equal(c.response.body.state, 'signed_in');
  assert.match(c.response.body.user_id, /^u-/, 'the Company saw the agent-assigned User ID');
  assert.equal(c.request.headers['poppy-version'], '1.0');
  assert.notEqual(c.response.body.user_id, c.response.body.account, 'User ID is not the account');
});

test('Mock: declining the consent ends in signin=error with no token', async () => {
  const a = await mockApp();
  const r = await signIn(a, { ws: 'm2', action: 'deny' });
  assert.equal(r.redirect.searchParams.get('error'), 'access_denied');
  assert.equal(r.redirect.searchParams.get('iss'), 'https://auth.company.example', 'iss is on error responses too');
  assert.match(r.cb.headers.get('location'), /signin=error/);
  assert.equal((await (await a.call('/api/state', undefined, 'm2')).json()).signedIn, false);
});

test('Mock: the consent endpoints refuse bad bodies and an unknown or reused id; workspaces are isolated', async () => {
  const a = await mockApp();
  const r = await signIn(a, { ws: 'm3' });
  assert.equal((await a.call(`/api/mock/consent?id=${r.redirect.searchParams.get('state')}`, undefined, 'm3')).status, 404);
  assert.equal((await a.call('/api/mock/consent', { id: 5, action: 'approve' }, 'm3')).status, 400);
  assert.equal((await a.call('/api/mock/consent', { id: 'x', action: 'maybe' }, 'm3')).status, 400);
  assert.equal((await a.call('/api/mock/consent', { id: 'nope', action: 'approve' }, 'm3')).status, 400);
  // another visitor cannot see or answer this visitor's consent
  const b = await a.call('/api/authorize', { scope: 'orders:read' }, 'm4');
  assert.equal(b.status, 409);
});

test('Mock: the Session User ID is stable for the Company and differs between visitors', async () => {
  const a = await mockApp();
  await signIn(a, { ws: 'u1' }); await signIn(a, { ws: 'u2' });
  const id = async (ws) => (await (await a.call('/api/call', { path: '/poppy/api/v1/me' }, ws)).json()).response.body.user_id;
  const u1 = await id('u1');
  assert.equal(await id('u1'), u1);
  assert.notEqual(await id('u2'), u1);
});

test('GET /api/verify/checks lists the checks and every defect', async () => {
  const a = await mockApp();
  const j = await (await a.call('/api/verify/checks')).json();
  assert.ok(j.checks.length >= 55);
  assert.ok(Object.keys(j.defects).length >= 25);
  assert.match(j.spec, /personalagentprotocol\.org\/docs\/1\.0\/spec/);
});

test('POST /api/verify/run in Mock: clean passes, a defect fails exactly its check, bad input is a 400', async () => {
  const a = await mockApp();
  const clean = await (await a.call('/api/verify/run', {})).json();
  assert.equal(clean.conformant, true, JSON.stringify(clean.results.filter((r) => r.status === 'fail')));
  assert.equal(clean.mode, 'mock');
  const bad = await (await a.call('/api/verify/run', { defects: ['no_protected_resources'] })).json();
  assert.equal(bad.conformant, false);
  assert.deepEqual(bad.results.filter((r) => r.status === 'fail').map((r) => r.id), ['as-protected-resources']);
  assert.equal((await a.call('/api/verify/run', { defects: ['nope'] })).status, 400);
  assert.equal((await a.call('/api/verify/run', { defects: Array(50).fill('no_pkce') })).status, 400);
});

test('POST /api/verify/run in Real: the suite runs with the real agent identity, and only the two typed hosts are contacted', async () => {
  const k = generateEs256Key();
  const agentKey = { privateKey: k.privateKey, publicJwk: k.publicJwk, kid: jwkThumbprint(k.publicJwk) };
  const base = 'https://agent.example';
  const seenHosts = new Set();
  const agentDocs = (url) => (new URL(url).pathname === '/client.json' ? jsonResponse(200, clientMetadata({ baseUrl: base, redirectUri: `${base}/cb` })) : jsonResponse(200, jwksDocument(agentKey.publicJwk, agentKey.kid)));
  const ref = createReference({ hosts: { 'agent.example': agentDocs } });
  const fetchImpl = (url, init) => { seenHosts.add(new URL(url).host); return ref.fetch(url, init); };
  const app = createApp({ agent: agentKey, hosted: false, baseUrl: base, sessions: createSessions(), health: health(), fetchImpl });
  const server = await new Promise((res) => { const s = http.createServer(app).listen(0, '127.0.0.1', () => res(s)); });
  opened.push(server);
  const url = `http://127.0.0.1:${server.address().port}/api/verify/run`;
  const post = (b) => fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', 'x-workspace': 'real1' }, body: JSON.stringify(b) });
  const r = await (await post({ origin: 'https://company.example', issuer: 'https://auth.company.example', probePath: '/poppy/api/v1/catalog' })).json();
  assert.equal(r.mode, 'real');
  const by = Object.fromEntries(r.results.map((x) => [x.id, x]));
  assert.equal(by['s-valid'].status, 'pass', JSON.stringify(by['s-valid']));
  assert.equal(by['s-aud'].status, 'pass');
  assert.equal(by['as-protected-resources'].status, 'pass');
  assert.equal(by['o-pkce'].status, 'skip', 'sign-in checks need a person against a real issuer');
  assert.match(by['o-pkce'].detail, /person/);
  assert.equal(by['s-ps384'].status, 'skip', 'the real agent publishes an ES256 key only');
  assert.equal(r.summary.fail, 0, JSON.stringify(r.results.filter((x) => x.status === 'fail')));
  assert.ok([...seenHosts].every((h) => ['company.example', 'auth.company.example', 'agent.example'].includes(h)), [...seenHosts].join());
  // a poppy.json that names an issuer other than the typed one: that issuer is never contacted
  const other = await (await post({ origin: 'https://company.example', issuer: 'https://different.example', probePath: '/poppy/api/v1/catalog' })).json();
  assert.equal(other.results.find((x) => x.id === 'as-issuer').status, 'skip');
  assert.ok(!seenHosts.has('different.example'));
  assert.equal((await post({ origin: 'https://company.example', issuer: 'https://auth.company.example', probePath: '//evil.example' })).status, 400);
});

test('POST /api/verify/run caps concurrent runs (429 busy) so a burst cannot starve the server', async () => {
  const a = await mockApp();
  const results = await Promise.all(Array.from({ length: 8 }, (_, i) => a.call('/api/verify/run', {}, `burst${i}`)));
  const statuses = results.map((r) => r.status);
  assert.ok(statuses.includes(200), 'some runs complete');
  assert.ok(statuses.includes(429), `a burst of 8 is refused beyond 3 in flight: ${statuses.join(',')}`);
  const busy = results.find((r) => r.status === 429);
  assert.equal(busy.headers.get('retry-after'), '2');
  assert.equal((await busy.json()).error, 'busy');
  // and the server is healthy afterwards
  assert.equal((await a.call('/api/verify/checks')).status, 200);
});
