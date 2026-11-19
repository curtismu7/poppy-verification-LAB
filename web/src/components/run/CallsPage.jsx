// Page 2: the controls that make the three moves, then every request in order as an expandable row (inspector style).
import Json, { POPPY_HOT } from "../Json";
import { buildRows } from "./callRows";

function Why({ why }) {
  return (
    <div className="rp-note">
      <span className="rp-note__lbl">Why this call</span>
      {Array.isArray(why) ? <ol>{why.map((w) => <li key={w}>{w}</li>)}</ol> : <p>{why}</p>}
    </div>
  );
}

function Row({ row, open }) {
  return (
    <li className="rp-call">
      <details open={open}>
        <summary className="rp-call__head" data-testid={`row-${row.id}`}>
          <span className="rp-method">{row.method}</span>
          <span className="rp-path">{row.path}</span>
          <span className={`rp-status rp-status--${row.tone}`}>{row.status == null ? "not run yet" : row.status}</span>
        </summary>
        <div className="rp-call__body">
          <Why why={row.why} />
          {row.kv.length > 0 && <dl className="rp-kv">{row.kv.map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}</dl>}
          {row.raw.length > 0 ? row.raw.map((r) => (
            <details key={r.label} className="rp-raw" open={r.decoded}><summary>{r.decoded ? r.label : `Raw: ${r.label}`}</summary><Json value={r.value} label={`${row.id} ${r.label}`} hot={POPPY_HOT} /></details>
          )) : <p className="muted">Nothing on the wire yet for this call.</p>}
        </div>
      </details>
    </li>
  );
}

// Every line carries its source (rule 2: a product claim needs one, else it is labelled UNVERIFIED).
const GAPS = [
  ["PingFederate", "13.1 documents client ID metadata documents (CIMD) and PAR, but publishes no protected_resources in its metadata. An agent must refuse without it (spec 3.2), so put a metadata layer in front, or ask for the setting.", "CIMD and PAR: the PingFederate 13.1 CIMD page. The missing protected_resources is from our own run on 2026-11-15, not from a Ping page: UNVERIFIED in the docs (the index shows no such setting, which is not conclusive)."],
  ["PingOne", "no CIMD client type found in our tests: the agent needs a registered client_id. PAR works. It expects the token endpoint as the assertion audience, where the spec wants the issuer.", "Our tests of one tenant on 2026-11-15; UNVERIFIED for other tenants. PAR and Private Key JWT: the PingOne application device-authorization page."],
  ["PingOne Advanced Identity Cloud", "documents CIMD profiles (no CIBA for those clients, redirects not followed); we have not tested it for protected_resources.", "The AIC CIMD page (docs.pingidentity.com, pingoneaic, am-oauth2, oauth2-cimd). Not run by us."],
  ["Every Company", "decides which agents it accepts (spec 4.1: it can refuse sign-in per client_id).", "Personal Agent Protocol 1.0, section 4.1."],
];

export default function CallsPage({ ui, c }) {
  const { info, state, busy, off, scopes, scope, setScope, origin, setOrigin, issuer, setIssuer, path, setPath, useResource, setUseResource, mismatch, as, pickAs } = c;
  const rows = buildRows(state);
  const d = info?.defaults || {};
  return (
    <section className="rp-page" aria-labelledby="rp-calls">
      <h2 id="rp-calls" className="rp-title rp-title--sm"><span className="step-num" data-n="2" aria-hidden="true"></span>The calls</h2>
      <p className="muted">Every request the agent makes, in order. Click a row to open it: the reason first, the raw wire underneath if you want it.</p>

      {(d.issuer || d.p1Issuer) && (
        <fieldset className="rp-as" aria-label="Authorization server">
          <legend>Authorization server</legend>
          <label className="inline"><input type="radio" name="as" checked={as === "pf"} disabled={!d.issuer} onChange={() => pickAs("pf")} />PingFederate <span className="rp-pre">{d.issuer ? "preconfigured" : "not configured here"}</span></label>
          <label className="inline"><input type="radio" name="as" checked={as === "p1"} disabled={!d.p1Issuer} onChange={() => pickAs("p1")} />PingOne <span className="rp-pre">{d.p1Issuer ? "preconfigured" : "not configured here"}</span></label>
        </fieldset>
      )}
      <div className="rp-gaps">
        <b>What's missing here (honest gaps)</b>
        <ul>{GAPS.map(([who, what, src]) => <li key={who}><b>{who}:</b> {what} <span className="muted">Source: {src}</span></li>)}</ul>
      </div>

      {ui}

      <div className="rp-controls">
        <p className="rp-controls__main">
          {/* ui-pattern: allow P9 Run it (1 click) is the one primary of the calls page: RunPanel passes plainNext there, so the Pager Next is plain (the static check cannot follow that prop) */}
          <button type="button" className="primary" onClick={c.oneClick} disabled={off || busy !== ""} data-testid="one-click">Run it (1 click)</button>{" "}
          <span className="muted">fills in this deployment's Company and issuer, reads the Company, then hands you to the authorization server to sign in.</span>
        </p>
        <div className="rp-fields">
          <div><label htmlFor="origin">Company origin</label>
            <input id="origin" value={origin} onChange={(e) => setOrigin(e.target.value)} placeholder="https://company.example" spellCheck={false} autoComplete="off" /></div>
          <div><label htmlFor="issuer">Authorization server issuer (must match what the Company publishes)</label>
            <input id="issuer" value={issuer} onChange={(e) => setIssuer(e.target.value)} placeholder="https://auth.example:9031" spellCheck={false} autoComplete="off" /></div>
        </div>
        <p className="rp-steps">
          <button type="button" onClick={c.discover} disabled={off || busy !== "" || !origin || !issuer} data-testid="discover">{busy === "discover" ? "Reading..." : "1. Read the Company"}</button>
          <button type="button" onClick={c.signIn} disabled={off || busy !== "" || !state?.discovery || !scope} data-testid="signin">2. Sign in as the agent</button>
          <button type="button" onClick={() => c.call()} disabled={off || busy !== "" || !state?.signedIn} data-testid="call">3. Call with token and Poppy-Session</button>
        </p>
        {!off && (
          <p className="muted rp-hint" data-testid="step-hint">
            {!state?.discovery ? "Start with Run it (1 click), or step 1."
              : !state?.signedIn ? "Next: 2. Sign in. When you come back, the call runs by itself."
              : "Signed in. 3 calls the Company again with a fresh Poppy-Session."}
          </p>
        )}
        <details className="rp-opts"><summary>Options: scope, resource indicator, path</summary>
          <label htmlFor="scope">Scope to ask for</label>
          <select id="scope" value={scope} onChange={(e) => setScope(e.target.value)} disabled={!scopes.length}>
            {scopes.length ? scopes.map((s) => <option key={s} value={s}>{s}</option>) : <option value="">(read the Company first)</option>}
          </select>
          <label className="inline" htmlFor="resource"><input id="resource" type="checkbox" checked={useResource} onChange={(e) => setUseResource(e.target.checked)} />Send the Company as the resource (RFC 8707)</label>
          <p className="muted">Off by default: PingFederate answers 400 to a resource URI it has not registered. Turn it on for an issuer that accepts it.</p>
          <label htmlFor="path">Path on the Company origin</label>
          <input id="path" value={path} onChange={(e) => setPath(e.target.value)} spellCheck={false} autoComplete="off" />
        </details>
        {(mismatch || state?.discovery) && (
          <ul className="facts" aria-label="Discovery checks">
            {(mismatch || state.discovery.checks).map((k) => <li key={k.id}><span className={`tag ${k.ok ? "tag--ok" : "tag--warn"}`}>{k.ok ? "pass" : k.level === "warn" ? "warn" : "fail"}</span> {k.note}</li>)}
          </ul>
        )}
      </div>

      <ul className="rp-calls">{rows.map((r, i) => <Row key={r.id} row={r} open={i === 0} />)}</ul>
    </section>
  );
}
