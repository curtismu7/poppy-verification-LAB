// The Verify tab: run the Personal Agent Protocol 1.0 checks against a Company and its issuer. Mock runs against the in-process
// reference (clean = every check passes; switch a defect on and the check that names it fails: a verifier that cannot fail proves
// nothing). Real runs the Session and metadata checks against the Company and issuer you type; sign-in checks need a person.
import { useEffect, useMemo, useState } from "react";
import { getJson, postJson } from "../api";
import Json from "./Json";

const LABEL = { pass: "Pass", fail: "Fail", warn: "Warn", skip: "Skipped" };
const GROUPS = ["Discovery", "Issuer metadata", "Poppy-Session", "Sign-in and tokens", "Resources and tokens"];

export default function VerifyPanel({ info }) {
  const [catalog, setCatalog] = useState(null);
  const [report, setReport] = useState(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [defects, setDefects] = useState([]);
  const [origin, setOrigin] = useState("");
  const [issuer, setIssuer] = useState("");
  const [probePath, setProbePath] = useState("/poppy/api/v1/me");
  const [filter, setFilter] = useState("all");
  const mock = info?.source !== "real";
  useEffect(() => { getJson("/api/verify/checks").then(setCatalog, () => setCatalog(null)); }, []);
  useEffect(() => { setReport(null); setMsg(""); }, [info?.source]);
  useEffect(() => { const d = info?.defaults; if (d?.origin) { setOrigin((v) => v || d.origin); setIssuer((v) => v || d.issuer); } }, [info]);

  const toggle = (d) => setDefects((cur) => (cur.includes(d) ? cur.filter((x) => x !== d) : [...cur, d]));
  const run = async () => {
    setBusy(true); setMsg("");
    const r = await postJson("/api/verify/run", mock ? { defects } : { origin, issuer, probePath });
    setBusy(false);
    if (!r.ok) { setReport(null); return setMsg(r.body.message || r.body.error || `HTTP ${r.status}`); }
    setReport(r.body);
  };

  const byId = useMemo(() => Object.fromEntries((report?.results ?? []).map((x) => [x.id, x])), [report]);
  const rows = (catalog?.checks ?? []).map((c) => ({ ...c, result: byId[c.id] }));
  const visible = rows.filter((r) => filter === "all" || (r.result && (filter === "problems" ? ["fail", "warn"].includes(r.result.status) : r.result.status === filter)));
  const s = report?.summary;

  return (
    <div className="vf" data-testid="verify-panel">
      <section className="rp-page">
        <p className="rp-eyebrow">Personal Agent Protocol · spec 1.0</p>
        <h2 className="rp-title rp-title--sm">Verify a Company against the published spec</h2>
        <p className="muted">{catalog ? `${catalog.checks.length} checks, each tied to a section of the ` : "Checks tied to the "}<a href={catalog?.spec ?? "https://personalagentprotocol.org/docs/1.0/spec"} target="_blank" rel="noreferrer">1.0 specification</a> (published 2026-11-14). A pass means this suite saw the right behaviour, not that the Company is certified.</p>

        {mock ? (
          <div className="rp-controls" data-testid="verify-mock">
            <p className="rp-controls__main"><b>Mock:</b> a reference Company and issuer built inside this app. Run it clean, then give it a deliberate defect and watch the check that names it fail.</p>
            <details>
              <summary>Defects to switch on ({defects.length} selected)</summary>
              <ul className="vf-defects">
                {Object.entries(catalog?.defects ?? {}).map(([d, text]) => (
                  <li key={d}><label className="inline"><input type="checkbox" checked={defects.includes(d)} onChange={() => toggle(d)} data-testid={`defect-${d}`} /> <code>{d}</code> <span className="muted">{text}</span></label></li>
                ))}
              </ul>
            </details>
          </div>
        ) : (
          <div className="rp-controls" data-testid="verify-real">
            <p className="rp-controls__main"><b>Real:</b> reads the Company and the issuer you name and sends Session probes with this agent's own key. Only those two hosts are contacted. Checks that need a person to sign in are skipped here; use the Run it tab for those.</p>
            <div className="rp-fields">
              <label>Company origin<input type="text" value={origin} onChange={(e) => setOrigin(e.target.value)} placeholder="https://company.example" data-testid="verify-origin" /></label>
              <label>Issuer<input type="text" value={issuer} onChange={(e) => setIssuer(e.target.value)} placeholder="https://auth.company.example" data-testid="verify-issuer" /></label>
              <label>Probe path<input type="text" value={probePath} onChange={(e) => setProbePath(e.target.value)} data-testid="verify-path" /></label>
            </div>
          </div>
        )}
        <p>
          <button type="button" className="primary" onClick={run} disabled={busy || !catalog || (!mock && (!origin || !issuer))} data-testid="verify-run">{busy ? "Running..." : "Run verification"}</button>
        </p>
        {msg && <p className="panel panel--warn" data-testid="verify-msg">{msg}</p>}

        {s && (
          <div data-testid="verify-summary">
            <p className={`vf-verdict ${report.conformant ? "vf-verdict--ok" : "vf-verdict--bad"}`} role="status">
              {report.conformant ? "No check failed." : `${s.fail} check${s.fail === 1 ? "" : "s"} failed.`} {s.pass} passed, {s.warn} warning{s.warn === 1 ? "" : "s"}, {s.skip} skipped of {s.total}.
              {report.mode === "mock" && report.defects?.length ? ` Defects on: ${report.defects.join(", ")}.` : ""}
            </p>
            <div className="vf-filter" role="group" aria-label="Show">
              {["all", "problems", "fail", "pass", "skip"].map((f) => <button key={f} type="button" aria-pressed={filter === f} onClick={() => setFilter(f)}>{f === "all" ? "All" : f === "problems" ? "Problems" : LABEL[f]}</button>)}
            </div>
          </div>
        )}

        {GROUPS.map((g) => {
          const inGroup = visible.filter((r) => r.group === g);
          if (!inGroup.length) return null;
          return (
            <section key={g} className="vf-group" aria-label={g}>
              <h3>{g}</h3>
              <ul className="vf-list">
                {inGroup.map((r) => (
                  <li key={r.id} className="vf-row" data-testid={`check-${r.id}`} data-status={r.result?.status ?? "idle"}>
                    <span className={`vf-chip vf-chip--${r.result?.status ?? "idle"}`}>{r.result ? LABEL[r.result.status] : "Not run"}</span>
                    <span className="vf-title">{r.title}{r.level === "should" ? <span className="muted"> (recommended)</span> : null}</span>
                    <span className="vf-spec muted">spec {r.spec}</span>
                    {r.result?.detail && <span className="vf-detail">{r.result.detail}</span>}
                  </li>
                ))}
              </ul>
            </section>
          );
        })}

        {report && <details className="rp-raw"><summary>Raw report</summary><Json value={report} label="Verification report" hot={["status", "conformant", "fail", "detail"]} /></details>}
      </section>
    </div>
  );
}
