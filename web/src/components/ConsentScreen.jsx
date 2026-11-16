// Mock only: the consent page of the reference issuer (spec 4.2: names the Company and the agent, lists every scope with what it
// can change, and says what happens next). Real mode never shows this: the real issuer serves its own page.
import { useEffect, useState } from "react";
import { getJson, postJson } from "../api";

const CHANGES = { none: "reads only", reversible: "can be undone", irreversible: "cannot be undone" };

export default function ConsentScreen({ id, onDone }) {
  const [c, setC] = useState(undefined);
  const [granted, setGranted] = useState([]);
  const [err, setErr] = useState("");
  useEffect(() => { getJson(`/api/mock/consent?id=${encodeURIComponent(id)}`).then((v) => { setC(v); setGranted(v.scopes.map((s) => s.name)); }, () => setC(null)); }, [id]);
  const answer = async (action) => {
    const r = await postJson("/api/mock/consent", { id, action, scopes: action === "approve" ? granted : undefined });
    if (!r.ok) return setErr(r.body.message || r.body.error || `HTTP ${r.status}`);
    onDone?.();
    window.location.assign(r.body.redirect);
  };
  if (c === undefined) return <p className="panel" role="status">Loading the consent request...</p>;
  if (c === null) return <p className="panel panel--warn" data-testid="consent-gone">This sign-in expired or was already answered. Go back and start again.</p>;
  return (
    <section className="rp-page vf-consent" aria-labelledby="consent-h" data-testid="consent">
      <p className="banner" role="status">MOCK ISSUER: this consent page is part of the reference issuer inside this app. A real authorization server shows its own page here. Tokens it issues are mock tokens.</p>
      <h2 id="consent-h" className="rp-title rp-title--sm">{c.company} wants to let an agent act for you</h2>
      <p>The agent <b>{c.clientName}</b> (<code>{c.clientId}</code>) asks for these permissions on your account at <b>{c.company}</b>. You choose which to give. It never gets more than you tick.</p>
      <ul className="vf-scopes">
        {c.scopes.map((s) => (
          <li key={s.name}>
            <label className="inline"><input type="checkbox" checked={granted.includes(s.name)} onChange={() => setGranted((g) => (g.includes(s.name) ? g.filter((x) => x !== s.name) : [...g, s.name]))} data-testid={`grant-${s.name}`} /> <b>{s.name}</b></label>
            <span> {s.description}. <span className="muted">{CHANGES[s.changes] ?? "may change data"}{s.personal_data ? ", includes personal data" : ""}.</span></span>
          </li>
        ))}
      </ul>
      {err && <p className="panel panel--warn">{err}</p>}
      <p>
        <button type="button" className="primary" onClick={() => answer("approve")} disabled={!granted.length} data-testid="consent-approve">Allow</button>{" "}
        <button type="button" onClick={() => answer("deny")} data-testid="consent-deny">Decline</button>
      </p>
    </section>
  );
}
