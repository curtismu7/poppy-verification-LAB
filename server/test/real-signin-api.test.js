// Real-mode headless sign-in at the API level: the opt-in gates, the env-only credentials, and the guarantee that neither the
// username nor the password ever appears in a response, a step, or the session log.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createApp } from '../src/app.js';
import { createSessions } from '../src/sessions.js';
import { createHealth } from '../src/health.js';
import { generateEs256Key, jwkThumbprint } from '../src/jose.js';
import { clientMetadata, jwksDocument } from '../src/agent.js';
import { createReference, COMPANY_ORIGIN, ISSUER } from '../src/reference/index.js';
import { jsonResponse } from '../src/reference/common.js';

const opened = [];
after(() => { for (const s of opened) s.close(); opened.length = 0; });
const health = () => createHealth({ runChecks: async () => [], intervalMs: 3_600_000 });

const page = (t, b) => new Response(`<!doctype html><html><head><title>${t}</title></head><body>${b}</body></html>`, { status: 200, headers: { 'content-type': 'text/html' } });
const input = (ty, n, v = '') => `<input type="${ty}" name="${n}" value="${v}">`;

/** A full fake lab: agent docs + reference Company/issuer, with the issuer host fronted by PF-style login and consent pages. */
async function lab({ user, password } = {}) {
  const k = generateEs256Key();
  const agentKey = { privateKey: k.privateKey, publicJwk: k.publicJwk, kid: jwkThumbprint(k.publicJwk) };
  const base = 'https://agent.example';
  const sentPasswords = [];
  const sentUsers = [];
  const seenHosts = new Set();
  const agentDocs = (url) => (new URL(url).pathname === '/client.json' ? jsonResponse(200, clientMetadata({ baseUrl: base, redirectUri: `${base}/cb` })) : jsonResponse(200, jwksDocument(agentKey.publicJwk, agentKey.kid)));
  const ref = createReference({ hosts: { 'agent.example': agentDocs } });
  ref.addHost(new URL(ISSUER).host, async (url, init = {}) => {
    const u = new URL(url);
    const method = String(init.method || 'GET').toUpperCase();
    const body = Object.fromEntries(new URLSearchParams(String(init.body ?? '')));
    if (method === 'GET' && u.pathname === '/authorize') {
      const s = await ref.issuer.startAuthorization(Object.fromEntries(u.searchParams));
      if (s.kind === 'redirect') return new Response(null, { status: 302, headers: { location: s.url } });
      if (s.kind === 'error') return page('Error', `<p>${s.error}: ${s.description}</p>`);
      return page('Sign in', `<form method="post" action="/resume">${input('hidden', 'consentId', s.id)}${input('text', 'pf.username')}${input('password', 'pf.pass')}${input('hidden', 'pf.ok')}${input('hidden', 'pf.adapterId', 'A')}</form>`);
    }
    if (method === 'POST' && u.pathname === '/resume') {
      if ('pf.pass' in body) { sentUsers.push(body['pf.username']); sentPasswords.push(body['pf.pass']); return page('Request for Approval', `<form method="post" action="/resume">${input('hidden', 'consentId', body.consentId)}${input('hidden', 'cSRFToken', 'tok')}${input('checkbox', 'scope', ref.issuer.pending(body.consentId)?.scopes.map((s) => s.name).join(' ') ?? '')}${input('hidden', 'pf.oauth.authz.consent')}</form>`); }
      const out = body['pf.oauth.authz.consent'] === 'deny' ? ref.issuer.deny(body.consentId) : ref.issuer.approve(body.consentId);
      return new Response(null, { status: 302, headers: { location: out.url } });
    }
    return ref.issuer.handle(url, init);
  });
  const fetchImpl = (url, init) => { seenHosts.add(new URL(url).host); return ref.fetch(url, init); };
  const app = createApp({ agent: agentKey, hosted: false, baseUrl: base, sessions: createSessions(), health: health(), fetchImpl });
  const server = await new Promise((res) => { const s = http.createServer(app).listen(0, '127.0.0.1', () => res(s)); });
  opened.push(server);
  const port = server.address().port;
  const post = (b) => fetch(`http://127.0.0.1:${port}/api/verify/run`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-workspace': 'r1' }, body: JSON.stringify(b) });
  return { post, seenHosts, sentUsers, sentPasswords, ref, base };
}

const REAL = { origin: COMPANY_ORIGIN, issuer: ISSUER, probePath: '/poppy/api/v1/catalog' };
const SCOPES = { read: 'orders:read', other: 'orders:write', escalate: 'account:close' };

test('signIn without the env configured: 400, and the suite is not run', async () => {
  delete process.env.PVL_SIGNIN_USER; delete process.env.PVL_SIGNIN_PASSWORD;
  const l = await lab();
  const res = await l.post({ ...REAL, signIn: true });
  assert.equal(res.status, 400);
  const j = await res.json();
  assert.equal(j.error, 'signin_unconfigured');
  assert.match(j.message, /PVL_SIGNIN_USER/);
});

test('signIn without signIn: true, or with env unset, runs exactly as before (sign-in checks skip with the person reason)', async () => {
  delete process.env.PVL_SIGNIN_USER; delete process.env.PVL_SIGNIN_PASSWORD;
  const l = await lab();
  const j = await (await l.post(REAL)).json();
  assert.equal(j.mode, 'real');
  const by = Object.fromEntries(j.results.map((x) => [x.id, x]));
  assert.equal(by['o-pkce'].status, 'skip');
  assert.match(by['o-pkce'].detail, /person/);
  assert.equal(j.summary.fail, 0);
});

test('a full signed-in Real run: the checks run, no credential ever appears in the response or the session log, and only the typed hosts are contacted', async () => {
  const user = 'pvl-user-name'; const password = 'pvl-password-value';
  process.env.PVL_SIGNIN_USER = user; process.env.PVL_SIGNIN_PASSWORD = password;
  const l = await lab();
  try {
    const res = await l.post({ ...REAL, signIn: true, scopes: SCOPES, mcpUrl: 'https://company.example/mcp' });
    const j = await res.json();
    assert.equal(res.status, 200);
    assert.equal(j.mode, 'real');
    const by = Object.fromEntries(j.results.map((x) => [x.id, x]));
    assert.equal(by['o-iss-success'].status, 'pass', JSON.stringify(by['o-iss-success']));
    assert.equal(by['o-iss-error'].status, 'pass', JSON.stringify(by['o-iss-error']));
    assert.equal(by['o-pkce'].status, 'pass', JSON.stringify(by['o-pkce']));
    assert.equal(by['a-signed-in'].status, 'pass', JSON.stringify(by['a-signed-in']));
    assert.equal(j.summary.fail, 0, JSON.stringify(j.results.filter((x) => x.status === 'fail')));
    // credentials nowhere in the response
    const text = JSON.stringify(j);
    assert.ok(!text.includes(password), 'the password leaked into the report');
    assert.ok(!text.includes(user), 'the username leaked into the report');
    // the fake PF saw the credentials exactly (this is the only place they go, and only over the guarded fetch)
    assert.equal(l.sentPasswords.filter((p) => p === password).length >= 1, true);
    assert.ok(l.sentUsers.every((u) => u === user));
    // only the Company, issuer and agent hosts were contacted
    assert.ok([...l.seenHosts].every((h) => ['company.example', 'auth.company.example', 'agent.example'].includes(h)), [...l.seenHosts].join());
  } finally { delete process.env.PVL_SIGNIN_USER; delete process.env.PVL_SIGNIN_PASSWORD; }
});

test('scopes must be read/other/escalate strings; a bad one is a 400', async () => {
  process.env.PVL_SIGNIN_USER = 'u'; process.env.PVL_SIGNIN_PASSWORD = 'p';
  const l = await lab();
  try {
    const res = await l.post({ ...REAL, signIn: true, scopes: { read: 'orders:read', evil: 'x' } });
    assert.equal(res.status, 400);
  } finally { delete process.env.PVL_SIGNIN_USER; delete process.env.PVL_SIGNIN_PASSWORD; }
});

test('GET /api/verify/checks says whether sign-in credentials are configured (boolean only)', async () => {
  process.env.PVL_SIGNIN_USER = 'u'; process.env.PVL_SIGNIN_PASSWORD = 'p';
  const l = await lab();
  const port = opened.at(-1).address().port;
  const get = async () => (await (await fetch(`http://127.0.0.1:${port}/api/verify/checks`)).json()).signin;
  assert.deepEqual(await get(), { configured: true });
  delete process.env.PVL_SIGNIN_PASSWORD;
  assert.deepEqual(await get(), { configured: false });
  delete process.env.PVL_SIGNIN_USER;
});
