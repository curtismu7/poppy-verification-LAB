// Compact JWS helpers for ES256 only. Zero dependencies. P-256 keys are built from createECDH, never from generateKeyPair
// (the async and sync EC key generators aborted on Node 20.20.2 in CI).
import crypto from 'node:crypto';

export const b64url = (input) => Buffer.from(input).toString('base64url');

/** A fresh P-256 key as { privateKey: KeyObject, publicJwk, privateJwk }. */
export function generateEs256Key() {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  const pub = ecdh.getPublicKey(); // 0x04 | X(32) | Y(32)
  const publicJwk = { kty: 'EC', crv: 'P-256', x: pub.subarray(1, 33).toString('base64url'), y: pub.subarray(33, 65).toString('base64url') };
  const privateJwk = { ...publicJwk, d: ecdh.getPrivateKey().toString('base64url') };
  return { privateKey: crypto.createPrivateKey({ key: privateJwk, format: 'jwk' }), publicJwk, privateJwk };
}

/** RFC 7638 thumbprint of an EC public JWK. */
export function jwkThumbprint(jwk) {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return crypto.createHash('sha256').update(canonical).digest('base64url');
}

export function signJws(header, payload, privateKey) {
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const sig = crypto.sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return `${input}.${sig.toString('base64url')}`;
}

/** Decode without verifying, for display. Returns null when the text is not a compact JWS. */
export function decodeJws(token) {
  const parts = typeof token === 'string' ? token.split('.') : [];
  if (parts.length !== 3) return null;
  try {
    return { header: JSON.parse(Buffer.from(parts[0], 'base64url').toString()), payload: JSON.parse(Buffer.from(parts[1], 'base64url').toString()) };
  } catch { return null; }
}

// ---- verification side (spec 4.1 and 5.2: Companies MUST accept ES256 and PS384; nothing else, never none or HS*) ----
export const ALLOWED_ALGS = ['ES256', 'PS384'];

/** A fresh RSA key (2048 bits) for PS384, the algorithm the spec asks for when a signature is made blind. */
export function generatePs384Key() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  return { privateKey, publicJwk: publicKey.export({ format: 'jwk' }) };
}

export function signJwsAlg(alg, header, payload, privateKey) {
  const input = `${b64url(JSON.stringify({ ...header, alg }))}.${b64url(JSON.stringify(payload))}`;
  const sig = alg === 'ES256'
    ? crypto.sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' })
    : crypto.sign('sha384', Buffer.from(input), { key: privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 });
  return `${input}.${sig.toString('base64url')}`;
}

/** Split a compact JWS without trusting it. Returns null for anything that is not three base64url segments of JSON. */
export function parseJws(token) {
  const parts = typeof token === 'string' ? token.split('.') : [];
  if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]*$/.test(p))) return null;
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    if (!header || typeof header !== 'object' || Array.isArray(header) || !payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
    return { header, payload, signingInput: `${parts[0]}.${parts[1]}`, signature: Buffer.from(parts[2], 'base64url') };
  } catch { return null; }
}

/**
 * Verify a parsed JWS against ONE public JWK. The algorithm comes from the header but must be on the allow-list and must fit the
 * key type, so alg none, HS256 and an RSA key signed as ES256 are all refused. Embedded keys (jwk, jku, x5u) are never read.
 */
export function verifyJws(parsed, jwk) {
  const alg = parsed?.header?.alg;
  if (!ALLOWED_ALGS.includes(alg)) return false;
  if (!jwk || (alg === 'ES256' && (jwk.kty !== 'EC' || jwk.crv !== 'P-256')) || (alg === 'PS384' && jwk.kty !== 'RSA')) return false;
  try {
    const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    return alg === 'ES256'
      ? crypto.verify('sha256', Buffer.from(parsed.signingInput), { key, dsaEncoding: 'ieee-p1363' }, parsed.signature)
      : crypto.verify('sha384', Buffer.from(parsed.signingInput), { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 }, parsed.signature);
  } catch { return false; }
}

/** RFC 7638 thumbprint for an EC or RSA public JWK. */
export function thumbprint(jwk) {
  const members = jwk.kty === 'RSA' ? { e: jwk.e, kty: jwk.kty, n: jwk.n } : { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  return crypto.createHash('sha256').update(JSON.stringify(members)).digest('base64url');
}
