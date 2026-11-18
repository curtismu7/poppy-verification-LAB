// Real-mode sign-in driver: an opt-in headless "browser" that signs the suite in against the typed issuer, so the sign-in checks can
// run in Real mode. It speaks PF-style HTML form login and consent (verified against PingFederate): find the login form by its
// password field, fill it from the environment, find the consent form by its *.consent hidden field, post allow or deny, and read the
// agent callback from the first redirect that carries it. It never follows the redirect to the agent and never calls /cb.
// The credentials arrive as constructor arguments only (from PVL_SIGNIN_USER / PVL_SIGNIN_PASSWORD); they are never logged, returned
// or put in a step, and they are only ever POSTed to the typed issuer (the guarded fetch refuses every other host).
import crypto from 'node:crypto';

const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const MAX_HOPS = 12;
// The suite asks for a scope the issuer must NOT know (o-scope-unknown); this made-up name is not a Company scope.
const UNKNOWN_SCOPE = 'pvl-unknown-scope';
const CIMD_SKIP = 'Real mode cannot publish a variant client document: the issuer would need a CIMD policy per URL, and the agent serves only its own document.';

const pkce = () => { const verifier = crypto.randomBytes(32).toString('base64url'); return { verifier, challenge: crypto.createHash('sha256').update(verifier).digest('base64url') }; };
const encode = (o) => new URLSearchParams(Object.entries(o).filter(([, v]) => v !== undefined)).toString();

// -- Minimal HTML form parsing (attribute values in double quotes, as PingFederate serves them) ---------------------------------------
const attr = (s, n) => (s.match(new RegExp(`\\b${n}\\s*=\\s*"([^"]*)"`, 'i')) ?? [])[1];
export function parseForms(html, baseUrl) {
  const out = [];
  for (const m of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const fields = [...m[2].matchAll(/<(input|button|select)\b([^>]*)>/gi)].map((f) => ({ tag: f[1].toLowerCase(), name: attr(f[2], 'name'), type: (attr(f[2], 'type') ?? (f[1].toLowerCase() === 'input' ? 'text' : undefined))?.toLowerCase(), value: attr(f[2], 'value') }));
    out.push({ action: attr(m[1], 'action'), method: (attr(m[1], 'method') ?? 'POST').toUpperCase(), fields });
  }
  return out.map((f) => ({ ...f, action: new URL(f.action ?? baseUrl, baseUrl).href }));
}
const pageTitle = (html) => (html.match(/<title>([^<]*)/i) ?? [])[1]?.trim();
const withPassword = (forms) => forms.find((f) => f.fields.some((x) => x.type === 'password'));
const withConsent = (forms) => forms.find((f) => f.fields.some((x) => /consent$/.test(x.name ?? '')));

/**
 * @param {{redirectUri: string, user: string, password: string, scopes?: {read?: string, other?: string, escalate?: string}, mcpUrl?: string}} o
 * `scopes` maps the suite's made-up scope names onto the ones this issuer knows: read (what the probe path needs), other (a scope that
 * must NOT satisfy the probe path), escalate (one that is never granted). An unmapped scope makes a check skip, so no Company scope
 * names are baked in here.
 */
export function createRealDriver({ redirectUri, user, password, scopes = {}, mcpUrl } = {}) {
  const scopeMap = { 'orders:read': scopes.read, 'orders:write': scopes.other, 'account:close': scopes.escalate, 'nonsense:all': UNKNOWN_SCOPE };
  const mapScope = (scope) => {
    const out = [];
    for (const t of String(scope ?? '').split(' ').filter(Boolean)) {
      const m = scopeMap[t];
      if (!m) return { error: `scope ${t} is not mapped for this issuer; pass scopes { read, other, escalate } on the run request` };
      out.push(m);
    }
    return { scope: out.join(' ') };
  };
  return {
    mcpUrl,
    signedInPath: '/poppy/api/v1/me',
    // Check ids this driver refuses to run in Real mode, with the honest reason.
    unsupported: (id) => (id.startsWith('o-cimd') || id === 'o-redirect-exact' ? CIMD_SKIP : null),
    methods({ kit, issuer, as, fetch }) {
      const cb = redirectUri ?? kit.redirectUri;
      const atCallback = (u) => { try { return u.startsWith(cb); } catch { return false; } };
      // A fresh cookie jar per sign-in: deterministic, and one check's session never leaks into the next.
      const jar = () => {
        const store = new Map(); // host -> Map(name -> value)
        return async (url, { method = 'GET', body, headers = {} } = {}) => {
          const u = new URL(url);
          const cookies = store.get(u.host);
          const res = await fetch(url, { method, body, redirect: 'manual', headers: { ...(cookies?.size ? { cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join('; ') } : {}), ...headers } });
          for (const c of res.headers.getSetCookie?.() ?? [res.headers.get('set-cookie')].filter(Boolean)) {
            const i = c.indexOf('=');
            const m = store.get(u.host) ?? new Map();
            m.set(c.slice(0, i), c.slice(i + 1).split(';')[0]);
            store.set(u.host, m);
          }
          return res;
        };
      };
      const readJson = async (res) => { try { return await res.clone().json(); } catch { return null; } };
      const postForm = async (url, body, req) => {
        const res = await req(url, { method: 'POST', body: encode(body), headers: { 'content-type': 'application/x-www-form-urlencoded' } });
        return { res, body: await readJson(res) };
      };
      const clientAuth = (o = {}) => {
        if (o.omit) return { client_id: kit.main.clientId };
        // `other` authenticates as a second agent identity (Real mode: only when the lab has one configured, else the suite skips those checks).
        const who = o.other ? kit.other : kit.main;
        return { client_id: who.clientId, client_assertion_type: ASSERTION_TYPE, client_assertion: kit.assertion({ identity: who, aud: issuer, ...o }) };
      };
      /** Follow redirects by hand, never into the agent callback: stop there and hand the Location back. */
      const follow = async (req, url, init) => {
        let cur = url;
        let opts = init;
        for (let i = 0; i < MAX_HOPS; i++) {
          let res;
          try { res = await req(cur, opts); } catch (e) { return { kind: 'error', reason: String(e.message).slice(0, 160) }; }
          opts = undefined;
          const loc = res.headers.get('location');
          if (res.status >= 300 && res.status < 400 && loc) {
            const next = new URL(loc, cur).href;
            if (atCallback(next)) return { kind: 'callback', url: next };
            cur = next;
            continue;
          }
          if (res.status === 200) return { kind: 'page', res, url: cur };
          return { kind: 'error', reason: `the issuer answered HTTP ${res.status}` };
        }
        return { kind: 'error', reason: 'too many redirects' };
      };
      const fromCallback = (u, state) => {
        const q = new URL(u).searchParams;
        if (q.get('state') !== state) return { ok: false, kind: 'state', reason: 'the redirect state does not match the one that was sent' };
        const iss = q.get('iss');
        if (q.get('error')) return { ok: false, kind: 'redirect', error: q.get('error'), iss, reason: `${q.get('error')}: ${q.get('error_description') ?? ''}` };
        return { ok: true, code: q.get('code'), iss };
      };
      /** Submit a parsed form: hidden and text fields copied, the password filled in, or the consent decision set. */
      const submit = (f, fill) => {
        const body = {};
        for (const x of f.fields) if (x.name && x.type !== 'checkbox' && x.type !== 'password') body[x.name] = x.value ?? '';
        fill(body, f);
        return { url: f.action, init: { method: 'POST', body: encode(body), headers: { 'content-type': 'application/x-www-form-urlencoded' } } };
      };
      return {
        /** A token request with a made-up code, to see whether the ASSERTION is accepted (invalid_grant) or refused (invalid_client). */
        tokenRaw: ({ assertion: a = {}, omit = false } = {}) => postForm(as.token_endpoint, { grant_type: 'authorization_code', code: 'not-a-real-code', redirect_uri: kit.redirectUri, code_verifier: 'x'.repeat(43), ...(omit ? { client_id: kit.main.clientId } : clientAuth(a)) }, jar()),
        async signIn({ scope = 'orders:read', resource, deny = false, wrongVerifier = false, clientPath = '/client.json', clientUrl, redirectSuffix = '', stopAtAuthorize = false, assertionAlg, noChallenge = false, tokenRedirectUri, redeemTwice = false, redirectUri: cbOverride, tokenResource } = {}) {
          if (clientUrl || (clientPath && clientPath !== '/client.json')) return { ok: false, kind: 'unsupported-client', reason: CIMD_SKIP };
          const mapped = mapScope(scope);
          if (mapped.error) return { ok: false, kind: 'scope', reason: mapped.error };
          const target = cbOverride ?? `${cb}${redirectSuffix}`;
          if (!as?.token_endpoint) return { ok: false, kind: 'error', reason: 'the issuer metadata could not be read' };
          const req = jar();
          const p = pkce();
          const state = crypto.randomBytes(8).toString('base64url');
          const params = { response_type: 'code', client_id: kit.main.clientId, redirect_uri: target, scope: mapped.scope, state, code_challenge: noChallenge ? undefined : p.challenge, code_challenge_method: noChallenge ? undefined : 'S256', resource, prompt: 'consent' };
          let query = params;
          if (as.pushed_authorization_request_endpoint) {
            const pushed = await postForm(as.pushed_authorization_request_endpoint, { ...params, ...clientAuth(assertionAlg ? { alg: assertionAlg } : {}) }, req);
            if (pushed.res.status !== 201) return { ok: false, kind: 'par', error: pushed.body?.error, reason: `PAR refused: ${pushed.body?.error}: ${pushed.body?.error_description ?? ''}` };
            query = { client_id: kit.main.clientId, request_uri: pushed.body.request_uri };
          }
          const first = await follow(req, `${as.authorization_endpoint}${as.authorization_endpoint.includes('?') ? '&' : '?'}${encode(query)}`, { method: 'GET' });
          if (first.kind !== 'page') {
            if (first.kind === 'callback') { const r = fromCallback(first.url, state); return r.ok ? { ok: false, kind: 'error', reason: 'the issuer redirected straight back without a page' } : r; }
            return { ok: false, kind: 'error', reason: first.reason ?? 'the authorization page did not open' };
          }
          if (stopAtAuthorize) return { ok: false, kind: 'consent', reason: 'authorization request accepted' };
          const finish = async (u) => {
            const r = fromCallback(u, state);
            if (!r.ok) return r;
            const redeem = () => postForm(as.token_endpoint, { grant_type: 'authorization_code', code: r.code, redirect_uri: tokenRedirectUri ?? target, code_verifier: wrongVerifier ? 'w'.repeat(43) : p.verifier, ...(tokenResource ?? resource ? { resource: tokenResource ?? resource } : {}), ...clientAuth(assertionAlg ? { alg: assertionAlg } : {}) }, req);
            const t = await redeem();
            const second = redeemTwice ? await redeem() : undefined;
            if (t.res.status !== 200) return { ok: false, iss: r.iss, error: t.body?.error, reason: `${t.body?.error}: ${t.body?.error_description ?? ''}` };
            return { ok: true, iss: r.iss, ...t.body, second: second && { status: second.res.status, error: second.body?.error } };
          };
          const html = await first.res.text();
          let forms = parseForms(html, first.url);
          let consentForm = withConsent(forms);
          if (!consentForm) {
            const login = withPassword(forms);
            if (!login) return { ok: false, kind: 'page', reason: `unsupported sign-in page: ${pageTitle(html) || 'untitled'}` };
            const posted = submit(login, (body) => {
              const userInput = login.fields.find((x) => x.type === 'text' && x.name);
              if (userInput) body[userInput.name] = user;
              const passInput = login.fields.find((x) => x.type === 'password' && x.name);
              if (passInput) body[passInput.name] = password;
              if (Object.hasOwn(body, 'pf.ok')) body['pf.ok'] = 'clicked';
            });
            const second = await follow(req, posted.url, posted.init);
            if (second.kind === 'callback') return finish(second.url);
            if (second.kind !== 'page') return { ok: false, kind: 'error', reason: second.reason ?? 'the login did not reach a page' };
            const html2 = await second.res.text();
            consentForm = withConsent(parseForms(html2, second.url));
            if (!consentForm) return { ok: false, kind: 'page', reason: `unsupported sign-in page: ${pageTitle(html2) || 'untitled'}` };
          }
          const consent = submit(consentForm, (body, f) => {
            const field = f.fields.find((x) => /consent$/.test(x.name ?? ''));
            body[field.name] = deny ? 'deny' : 'allow';
            if (!deny) { const cb2 = f.fields.find((x) => x.type === 'checkbox' && x.name === 'scope'); if (cb2) body.scope = cb2.value; }
          });
          const third = await follow(req, consent.url, consent.init);
          if (third.kind === 'callback') return finish(third.url);
          return { ok: false, kind: 'page', reason: third.reason ?? 'the consent submit did not redirect back to the agent' };
        },
        async refresh(token, scope, { other = false, resource } = {}) {
          if (!as?.token_endpoint) return { ok: false, reason: 'the issuer metadata could not be read' };
          let mapped;
          if (scope) { mapped = mapScope(scope); if (mapped.error) return { ok: false, reason: mapped.reason ?? mapped.error }; }
          const t = await postForm(as.token_endpoint, { grant_type: 'refresh_token', refresh_token: token, ...(mapped?.scope ? { scope: mapped.scope } : {}), ...(resource ? { resource } : {}), ...clientAuth({ other }) }, jar());
          return t.res.status === 200 ? { ok: true, ...t.body } : { ok: false, error: t.body?.error, reason: `${t.body?.error}: ${t.body?.error_description ?? ''}` };
        },
        async revoke(token, { other = false } = {}) {
          if (!as?.revocation_endpoint) return { ok: false, reason: 'the issuer publishes no revocation_endpoint' };
          const t = await postForm(as.revocation_endpoint, { token, token_type_hint: 'refresh_token', ...clientAuth({ other }) }, jar());
          return t.res.status === 200 ? { ok: true } : { ok: false, reason: `${t.body?.error}` };
        },
      };
    },
  };
}
