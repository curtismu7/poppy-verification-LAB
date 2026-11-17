// Drives the in-process reference issuer so the suite can sign in by itself (Mock mode). It speaks to the issuer the way an agent
// does: PAR when offered, the authorization request, consent (approved or denied by the "person" here), then the token request.
import crypto from 'node:crypto';
import { MCP_URL, ISSUER } from '../reference/common.js';

const pkce = () => { const verifier = crypto.randomBytes(32).toString('base64url'); return { verifier, challenge: crypto.createHash('sha256').update(verifier).digest('base64url') }; };
const form = (o) => new URLSearchParams(Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined))).toString();
const POST = { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' } };

export function createReferenceDriver(ref) {
  return {
    mcpUrl: MCP_URL,
    signedInPath: '/poppy/api/v1/me',
    methods({ kit }) {
      const assertion = (o = {}) => kit.assertion({ identity: kit.main, ...o });
      const post = async (path, body) => {
        const res = await ref.fetch(`${ISSUER}${path}`, { ...POST, body: form(body) });
        let json = null; try { json = await res.clone().json(); } catch { /* none */ }
        return { res, body: json };
      };
      // `other` authenticates as the second made-up agent (its own key and client_id); `clientId` names a variant client URL that
      // is signed with the main key (the variant documents publish the main jwks); `omit` sends no assertion at all.
      const clientAuth = (o = {}) => {
        if (o.omit) return { client_id: o.clientId ?? kit.main.clientId };
        const who = o.other ? kit.other : kit.main;
        return { client_id: o.clientId ?? who.clientId, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: kit.assertion({ identity: who, ...o.assertion, ...(o.clientId ? { clientId: o.clientId } : {}) }) };
      };
      return {
        /** A token request with a made-up code, to see whether the ASSERTION is accepted (invalid_grant) or refused (invalid_client). */
        tokenRaw: ({ assertion: a = {}, omit = false } = {}) => post('/token', { grant_type: 'authorization_code', code: 'not-a-real-code', redirect_uri: kit.redirectUri, code_verifier: 'x'.repeat(43), ...clientAuth({ omit, assertion: a }) }),
        async signIn({ scope = 'orders:read', resource, deny = false, wrongVerifier = false, clientPath = '/client.json', clientUrl, redirectSuffix = '', stopAtAuthorize = false, assertionAlg, noChallenge = false, tokenRedirectUri, redeemTwice = false, redirectUri, tokenResource } = {}) {
          const clientId = clientUrl ?? `${new URL(kit.main.clientId).origin}${clientPath}`;
          const variant = clientId !== kit.main.clientId;
          const p = pkce();
          const state = crypto.randomBytes(8).toString('base64url');
          const params = { response_type: 'code', client_id: clientId, redirect_uri: redirectUri ?? `${kit.redirectUri}${redirectSuffix}`, scope, state, code_challenge: noChallenge ? undefined : p.challenge, code_challenge_method: noChallenge ? undefined : 'S256', resource, prompt: 'consent' };
          let query = params;
          const metadata = ref.issuer.metadata();
          if (metadata.pushed_authorization_request_endpoint) {
            // PAR for EVERY client, variants included: with a required-PAR issuer a variant must be refused for ITS OWN fault,
            // not because it skipped the push (the pass-by-accident the review found).
            const pushed = await post('/par', { ...params, ...clientAuth({ clientId: variant ? clientId : undefined, assertion: { alg: assertionAlg } }) });
            if (pushed.res.status !== 201) return { ok: false, kind: 'par', error: pushed.body?.error, reason: `PAR refused: ${pushed.body?.error}: ${pushed.body?.error_description ?? ''}` };
            query = { client_id: clientId, request_uri: pushed.body.request_uri };
          }
          const start = await ref.issuer.startAuthorization(query);
          if (start.kind === 'error') return { ok: false, kind: 'error', error: start.error, reason: `${start.error}: ${start.description}` };
          if (start.kind === 'redirect') { const u = new URL(start.url); return { ok: false, kind: 'redirect', error: u.searchParams.get('error'), iss: u.searchParams.get('iss'), reason: u.searchParams.get('error_description') }; }
          if (stopAtAuthorize) return { ok: false, kind: 'consent', reason: 'authorization request accepted' };
          const out = deny ? ref.issuer.deny(start.id) : ref.issuer.approve(start.id);
          const u = new URL(out.url);
          if (u.searchParams.get('error')) return { ok: false, kind: 'redirect', error: u.searchParams.get('error'), iss: u.searchParams.get('iss'), reason: u.searchParams.get('error_description') };
          const code = u.searchParams.get('code');
          const redeem = () => post('/token', { grant_type: 'authorization_code', code, redirect_uri: tokenRedirectUri ?? params.redirect_uri, code_verifier: wrongVerifier ? 'w'.repeat(43) : p.verifier, resource: tokenResource ?? resource, ...clientAuth({ assertion: { alg: assertionAlg } }) });
          const t = await redeem();
          const second = redeemTwice ? await redeem() : undefined;
          if (t.res.status !== 200) return { ok: false, iss: u.searchParams.get('iss'), error: t.body?.error, reason: `${t.body?.error}: ${t.body?.error_description ?? ''}` };
          return { ok: true, iss: u.searchParams.get('iss'), ...t.body, second: second && { status: second.res.status, error: second.body?.error } };
        },
        async refresh(token, scope, { other = false, resource } = {}) { const t = await post('/token', { grant_type: 'refresh_token', refresh_token: token, scope, resource, ...clientAuth({ other }) }); return t.res.status === 200 ? { ok: true, ...t.body } : { ok: false, error: t.body?.error, reason: `${t.body?.error}: ${t.body?.error_description ?? ''}` }; },
        async revoke(token, { other = false } = {}) { const t = await post('/revoke', { token, token_type_hint: 'refresh_token', ...clientAuth({ other }) }); return t.res.status === 200 ? { ok: true } : { ok: false, reason: `${t.body?.error}` }; },
      };
    },
  };
}
