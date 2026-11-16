// The in-process "network" of Mock mode: three made-up hosts answered by handlers in this process. No socket is opened, so the
// netguard's zero-outbound rule holds by construction. Extra hosts (the test agents of the verification suite) are added by the caller.
import { createIssuer } from './issuer.js';
import { createCompany } from './company.js';
import { COMPANY_ORIGIN, ISSUER, DEFECTS, nowSeconds } from './common.js';

export { DEFECTS, COMPANY_ORIGIN, ISSUER };
export { MCP_URL, COMPANY_DOMAIN, AGENT_ORIGIN, SCOPES } from './common.js';

/**
 * @param {{defects?: string[], now?: () => number, hosts?: Record<string, (url: string, init?: object) => Promise<Response>|Response>, parRequired?: boolean}} o
 * `hosts` maps a host name to a handler; the reference adds company.example and auth.company.example.
 */
export function createReference({ defects = [], now = nowSeconds, hosts = {}, parRequired = false } = {}) {
  const unknown = defects.filter((d) => !Object.hasOwn(DEFECTS, d));
  if (unknown.length) throw new RangeError(`unknown defect: ${unknown.join(', ')}`);
  const set = new Set(defects);
  const table = new Map(Object.entries(hosts));
  // The fetch both servers use to read an agent's documents: it goes through the same in-process table.
  const fetchImpl = (url, init) => fetchAny(url, init);
  const issuer = createIssuer({ defects: set, now, fetchImpl, parRequired });
  const company = createCompany({ defects: set, now, issuer, fetchImpl });
  table.set(new URL(COMPANY_ORIGIN).host, (u, i) => company.handle(u, i));
  table.set(new URL(ISSUER).host, (u, i) => issuer.handle(u, i));
  async function fetchAny(url, init = {}) {
    const u = new URL(url);
    const h = table.get(u.host);
    if (!h) throw new TypeError(`fetch failed: ${u.host} is not a host of the in-process network`);
    const res = await h(u.href, init);
    // fetch semantics: only redirect:'follow' follows a Location (at most 3 hops); 'manual' hands the 3xx back, as a real fetch does.
    if (init.redirect === 'follow' && res.status >= 300 && res.status < 400 && res.headers.get('location') && (init.hops ?? 0) < 3) {
      return fetchAny(new URL(res.headers.get('location'), u).href, { ...init, hops: (init.hops ?? 0) + 1 });
    }
    return res;
  }
  return { fetch: fetchAny, issuer, company, defects: [...set], addHost: (host, handler) => table.set(host, handler), hostNames: () => [...table.keys()] };
}
