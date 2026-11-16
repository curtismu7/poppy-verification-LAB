// CIMD resolution (spec 4.1), shared by the issuer and the Company: the client_id is an HTTPS URL that returns the client metadata,
// fetched WITHOUT following redirects (CIMD draft 5), with the same-domain rules for jwks_uri and redirect_uris.
import { isBlockedAddress } from './common.js';

export function makeClientResolver({ fetchImpl, has, OAuthError }) {
  return async function resolveClient(clientId) {
    let u;
    try { u = new URL(String(clientId)); } catch { throw new OAuthError('invalid_client', 'client_id is not a URL', 401); }
    if (u.protocol !== 'https:' || u.username || u.password || u.hash) throw new OAuthError('invalid_client', 'client_id must be an https URL without credentials or fragment', 401);
    if (isBlockedAddress(u.hostname)) throw new OAuthError('invalid_client', 'client_id points at a loopback, private or link-local address', 401);
    const get = async (url) => {
      const res = await fetchImpl(url, { redirect: has('follow_redirects') ? 'follow' : 'manual', headers: { accept: 'application/json' } });
      if (res.status !== 200) throw new OAuthError('invalid_client', `client metadata answered ${res.status} (redirects are not followed; only 200 is accepted)`, 401);
      try { return await res.json(); } catch { throw new OAuthError('invalid_client', 'client metadata is not JSON', 401); }
    };
    const meta = await get(u.href);
    if (meta.client_id !== u.href) throw new OAuthError('invalid_client', 'client_id in the document does not equal the URL it was fetched from', 401);
    let j;
    try { j = new URL(meta.jwks_uri); } catch { throw new OAuthError('invalid_client', 'jwks_uri is not a URL', 401); }
    if (j.protocol !== 'https:' || (j.host !== u.host && !has('jwks_other_host'))) throw new OAuthError('invalid_client', 'jwks_uri must be https on the same domain as client_id', 401);
    if (isBlockedAddress(j.hostname)) throw new OAuthError('invalid_client', 'jwks_uri points at a loopback, private or link-local address', 401);
    for (const r of meta.redirect_uris ?? []) {
      let ru; try { ru = new URL(r); } catch { throw new OAuthError('invalid_client', 'redirect_uris holds a value that is not a URL', 401); }
      const loopback = ['127.0.0.1', '[::1]', 'localhost'].includes(ru.hostname);
      if (!(loopback || (ru.protocol === 'https:' && ru.host === u.host))) throw new OAuthError('invalid_client', 'each redirect_uri must be https on the client_id domain, or a loopback redirect', 401);
    }
    if (meta.token_endpoint_auth_method !== 'private_key_jwt') throw new OAuthError('invalid_client', 'token_endpoint_auth_method must be private_key_jwt', 401);
    const jwks = await get(j.href);
    return { clientId: u.href, meta, keys: Array.isArray(jwks?.keys) ? jwks.keys : [] };
  };
}
