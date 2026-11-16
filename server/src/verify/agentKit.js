// The verification suite plays a Personal Agent and, on purpose, a faulty one. This kit builds every JWT it needs with full control
// over the fields a Company must check: typ, alg, aud, htu, htm, iat, jti, ath, the delegation and its lifetime and signer.
// P-256 keys come from createECDH (see jose.js); RSA only for PS384.
import crypto from 'node:crypto';
import { generateEs256Key, generatePs384Key, signJwsAlg, thumbprint, b64url } from '../jose.js';
import { AGENT_ORIGIN, ISSUER, jsonResponse, rand } from '../reference/common.js';

const nowSeconds = () => Math.floor(Date.now() / 1000);

function identityFrom(clientId, es, ps) {
  const eskid = thumbprint(es.publicJwk);
  const keys = [{ ...es.publicJwk, kid: eskid, alg: 'ES256', use: 'sig' }];
  let pskid = null;
  if (ps) { pskid = thumbprint(ps.publicJwk); keys.push({ ...ps.publicJwk, kid: pskid, alg: 'PS384', use: 'sig' }); }
  return { clientId, es, ps, kid: eskid, pskid, jwks: { keys } };
}

/** @param {{main?: object, now?: () => number}} o  `main` lets the real lab agent be the identity (clientId, kid, privateKey, publicJwk). */
export function createAgentKit({ origin = AGENT_ORIGIN, main = null, redirectUri, now = nowSeconds, withSecondAgent = true } = {}) {
  const mainId = main
    ? { clientId: main.clientId, es: { privateKey: main.privateKey, publicJwk: main.publicJwk }, ps: null, kid: main.kid, pskid: null, jwks: { keys: [{ ...main.publicJwk, kid: main.kid, alg: 'ES256', use: 'sig' }] } }
    : identityFrom(`${origin}/client.json`, generateEs256Key(), generatePs384Key());
  const other = withSecondAgent && !main ? identityFrom(`${origin}/other/client.json`, generateEs256Key(), null) : null;
  const rogue = generateEs256Key(); // a key that no jwks_uri publishes
  const delegated = generateEs256Key();
  const userId = `u-${rand(12)}`;
  const sid = `sid-${rand(16)}`;
  const cb = redirectUri ?? `${origin}/cb`;

  const clientDoc = (id, extra = {}) => ({ client_id: id.clientId, client_name: 'Verification agent', redirect_uris: [cb], grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'private_key_jwt', token_endpoint_auth_signing_alg: 'ES256', jwks_uri: id.clientId.replace(/client\.json$/, 'jwks.json'), ...extra });

  /** The handlers for the made-up agent hosts of Mock mode. Real mode serves the real agent's documents from the app itself. */
  function hosts() {
    const h = {};
    h[new URL(origin).host] = (url) => {
      const p = new URL(url).pathname;
      if (p === '/client.json') return jsonResponse(200, clientDoc(mainId));
      if (p === '/jwks.json') return jsonResponse(200, mainId.jwks);
      if (other && p === '/other/client.json') return jsonResponse(200, clientDoc(other));
      if (other && p === '/other/jwks.json') return jsonResponse(200, other.jwks);
      // A client whose metadata URL redirects (CIMD: not followed) and whose document names the URL it was first asked for.
      if (p === '/redirecting/client.json') return new Response(null, { status: 302, headers: { location: `${origin}/redirecting/real.json` } });
      if (p === '/redirecting/real.json') return jsonResponse(200, { ...clientDoc(mainId), client_id: `${origin}/redirecting/client.json` });
      if (p === '/redirecting/jwks.json') return jsonResponse(200, mainId.jwks);
      // jwks_uri on another host than the client_id (spec 4.1: same domain).
      if (p === '/otherhost/client.json') return jsonResponse(200, { ...clientDoc(mainId), client_id: `${origin}/otherhost/client.json`, jwks_uri: `https://keys.${new URL(origin).host}/jwks.json` });
      // The document names a different client_id than its own URL.
      if (p === '/mismatch/client.json') return jsonResponse(200, { ...clientDoc(mainId), client_id: `${origin}/someone-else/client.json` });
      return jsonResponse(404, { error: 'not_found' });
    };
    h[`keys.${new URL(origin).host}`] = () => jsonResponse(200, mainId.jwks);
    return h;
  }

  const delegationJwt = ({ identity = mainId, lifetime = 3600, typ = 'poppy-delegation+jwt', alg = 'ES256', signer = null, cnf = delegated.publicJwk, iat = now(), extra = {} } = {}) => {
    const key = signer ? signer.privateKey : (alg === 'PS384' ? identity.ps.privateKey : identity.es.privateKey);
    const kid = signer ? thumbprint(signer.publicJwk ?? identity.es.publicJwk) : (alg === 'PS384' ? identity.pskid : identity.kid);
    return signJwsAlg(alg, { typ, kid }, { iss: identity.clientId, iat, exp: iat + lifetime, jti: rand(12), cnf: { jwk: cnf }, ...extra }, key);
  };

  /**
   * One Poppy-Session header. Everything defaults to a correct request; each test breaks exactly one thing.
   * `claims` and `header` merge over the defaults (a value of undefined deletes the member).
   */
  function session({ method = 'GET', url, accessToken, identity = mainId, delegation, noDelegation = false, claims = {}, header = {}, now: at = now(), sub = userId, signWith } = {}) {
    const d = noDelegation ? undefined : (delegation ?? delegationJwt({ identity, iat: at }));
    const payload = { iss: identity.clientId, aud: ISSUER, sid, sub, htm: method.toUpperCase(), htu: String(url).split('#')[0].split('?')[0], iat: at, jti: rand(12) };
    if (accessToken) payload.ath = crypto.createHash('sha256').update(accessToken).digest('base64url');
    for (const [k, v] of Object.entries(claims)) { if (v === undefined) delete payload[k]; else payload[k] = v; }
    const hdr = { typ: 'poppy-session+jwt', kid: noDelegation ? identity.kid : thumbprint(delegated.publicJwk), ...(d ? { poppy_dlg: d } : {}) };
    for (const [k, v] of Object.entries(header)) { if (v === undefined) delete hdr[k]; else hdr[k] = v; }
    const alg = hdr.alg ?? 'ES256';
    if (alg === 'none') return `${b64url(JSON.stringify({ ...hdr, alg }))}.${b64url(JSON.stringify(payload))}.`;
    if (alg === 'HS256') {
      const input = `${b64url(JSON.stringify({ ...hdr, alg }))}.${b64url(JSON.stringify(payload))}`;
      return `${input}.${crypto.createHmac('sha256', 'not-a-secret').update(input).digest('base64url')}`;
    }
    const key = signWith ?? (noDelegation ? identity.es.privateKey : delegated.privateKey);
    return signJwsAlg('ES256', hdr, payload, key);
  }

  /** A client assertion (spec 4.1). aud defaults to the issuer; lifetime to 60 seconds. */
  function assertion({ identity = mainId, aud = ISSUER, lifetime = 60, jti = rand(12), alg = 'ES256', iat = now() } = {}) {
    const key = alg === 'PS384' ? identity.ps.privateKey : identity.es.privateKey;
    const kid = alg === 'PS384' ? identity.pskid : identity.kid;
    return signJwsAlg(alg, { typ: 'client-authentication+jwt', kid }, { iss: identity.clientId, sub: identity.clientId, aud, iat, exp: iat + lifetime, jti }, key);
  }

  return { main: mainId, other, rogue, delegated, userId, sid, redirectUri: cb, clientDoc, hosts, delegationJwt, session, assertion };
}
