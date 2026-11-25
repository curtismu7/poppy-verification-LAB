import { useCallback, useEffect, useRef, useState } from "react";
import { getJson, postJson } from "../api";
import Json, { POPPY_HOT } from "./Json";
import Pager from "./run/Pager";
import IntroPage from "./run/IntroPage";
import CallsPage from "./run/CallsPage";
import TokenPage from "./run/TokenPage";

const ERR = { issuer_mismatch: "The issuer you typed is not the one the Company publishes.", agent_not_configured: "Set PVL_AGENT_BASE_URL to the https URL the issuer can reach, then restart.", discover_first: "Read the Company first.", sign_in_first: "Sign in first.", discovery_failed: "Discovery has a failing check, so this agent will not sign in (spec 3.2)." };
// A server message that names the real values (the issuer the Company publishes, the host that failed) beats a generic one.
const say = (r) => (["issuer_mismatch", "upstream", "par_failed", "authorize_refused", "discovery_failed"].includes(r.body.error) ? r.body.message : ERR[r.body.error]) || r.body.message || r.body.error || `HTTP ${r.status}`;

const PAGES = ["What & why", "The calls", "Token & session"];
// Coming back from the authorization server (?signin=ok|error) lands on the calls page, where the result is.
const startPage = () => (new URLSearchParams(window.location.search).get("signin") ? 2 : 1);

export default function RunPanel({ info, resetSignal }) {
  const [page, setPage] = useState(startPage);
  const [origin, setOrigin] = useState("");
  const [issuer, setIssuer] = useState("");
  const [scope, setScope] = useState("");
  const [path, setPath] = useState("/poppy/api/v1/me");
  const [state, setState] = useState(null);
  const [busy, setBusy] = useState("");
  const [msg, setMsg] = useState("");
  const [mismatch, setMismatch] = useState(null);
  const [useResource, setUseResource] = useState(false);
  const [as, setAs] = useState("pf");

  const refresh = useCallback(() => getJson("/api/state").then((s) => {
    setState(s);
    if (s.config) { setOrigin((v) => v || s.config.origin); setIssuer((v) => v || s.config.issuer); setScope((v) => v || s.config.scope); }
    else if (info?.hosted && info?.reference) {
      // Mock: the reference Company and issuer are known, so the form is filled in.
      setOrigin((v) => v || info.reference.origin); setIssuer((v) => v || info.reference.issuer); setScope((v) => v || "orders:read");
    } else if (info?.defaults?.origin) {
      // One-click defaults (owner rule 2026-11-14): the deployment names its own Company and issuer.
      setOrigin((v) => v || info.defaults.origin); setIssuer((v) => v || info.defaults.issuer); if (info.defaults.scope) setScope((v) => v || info.defaults.scope);
    }
  }, () => setState(null)), [info]);
  useEffect(() => { refresh(); }, [refresh, resetSignal]);
  useEffect(() => {
    const q = new URLSearchParams(window.location.search).get("signin");
    if (q === "ok") setMsg("Signed in. The token on the last page is the one the authorization server issued (a mock token in Mock mode).");
    else if (q === "error") setMsg("Sign-in failed. The rows below show the authorization server's answer.");
  }, []);

  // The radio pair preselects an issuer the deployment configured; the typed value stays editable.
  const pickAs = (which) => { setAs(which); const v = which === "p1" ? info?.defaults?.p1Issuer : info?.defaults?.issuer; if (v) setIssuer(v); };

  const run = async (name, fn) => {
    setBusy(name); setMsg("");
    window.dispatchEvent(new CustomEvent("pv:run-start"));
    let ok = true; try { await fn(); } catch { ok = false; }
    setBusy("");
    await refresh();
    // Tell Story the run ended only when the rows (or the error) are actually on the page: the run-done bubbles point at what the page shows.
    const announce = () => window.dispatchEvent(new CustomEvent("pv:run-end", { detail: { ok } }));
    if (ok) {
      let n = 0;
      const waitPaint = () => { if (document.querySelector(".rp-status--ok, .rp-status--warn") || n++ > 40) announce(); else requestAnimationFrame(waitPaint); };
      requestAnimationFrame(waitPaint);
    } else setTimeout(announce, 150);
  };
  const discover = () => run("discover", async () => {
    setMismatch(null);
    const r = await postJson("/api/discover", { origin, issuer });
    if (!r.ok) { setMismatch(r.body.discovery?.checks ?? null); return setMsg(r.status === 502 ? `Could not reach the Company or the issuer: ${r.body.message}. Check ${origin} and ${issuer}.` : say(r)); }
    const offered = Object.keys(r.body.poppy?.auth?.scopes ?? {});
    setScope(offered.includes("accounts:read") ? "accounts:read" : offered.includes("orders:read") ? "orders:read" : offered[0] ?? "");
    setMsg(r.body.ok ? "The Company's documents pass every check." : "The Company's documents have problems; see the checks.");
  });
  const signIn = () => run("authorize", async () => {
    const r = await postJson("/api/authorize", { scope, resource: useResource, from: "run", story: window.__storyOn === true });
    if (!r.ok) return setMsg(say(r));
    window.location.assign(r.body.url);
  });
  const oneClick = () => run("one-click", async () => {
    const r = await postJson("/api/discover", { origin, issuer });
    if (!r.ok) { setMismatch(r.body.discovery?.checks ?? null); return setMsg(r.status === 502 ? `Could not reach the Company or the issuer: ${r.body.message}. Check ${origin} and ${issuer}.` : say(r)); }
    const offered = Object.keys(r.body.poppy?.auth?.scopes ?? {});
    const chosen = offered.includes("accounts:read") ? "accounts:read" : offered.includes("orders:read") ? "orders:read" : offered[0] ?? "";
    if (chosen) setScope(chosen);
    const a = await postJson("/api/authorize", { scope: chosen, from: "run", story: window.__storyOn === true });
    if (!a.ok) return setMsg((r.body.ok ? "The Company's documents pass every check. " : "The Company's documents have problems; see the checks. ") + say(a));
    window.location.assign(a.body.url);
  });
  const call = (auto = false) => run("call", async () => {
    const r = await postJson("/api/call", { path });
    if (!r.ok) return setMsg(say(r));
    if (auto) setMsg("Signed in, then called the Company with the token and a fresh Poppy-Session: see the call row below.");
  });

  const hosted = info?.hosted === true;
  const unknownMode = info === undefined || info === null; // until the server says live or hosted, no action is offered
  const off = unknownMode; // Mock is fully usable (rule 19); only an unknown mode turns the actions off

  // Back from a good sign-in, make the call the person came for, once. Only when the newest step is that sign-in's
  // token, so a reload of ?signin=ok after the call does not call again.
  const autoCall = useRef(new URLSearchParams(window.location.search).get("signin") === "ok");
  useEffect(() => {
    if (!autoCall.current || off || busy || !state?.signedIn) return;
    autoCall.current = false;
    const last = state.steps?.[state.steps.length - 1];
    if (last?.kind === "token" && !last.error) call(true);
  }, [state, off, busy]); // eslint-disable-line react-hooks/exhaustive-deps
  const scopes = state?.discovery?.poppy?.auth?.scopes ? Object.keys(state.discovery.poppy.auth.scopes) : [];
  const notices = (
    <>
      {hosted && <p className="panel" data-testid="mock-note">Mock: the Company is <code>{info?.reference?.origin}</code> and the issuer is <code>{info?.reference?.issuer}</code>, both built into this app. Signing in shows the reference issuer's consent screen.</p>}
      {info && !info.configured && !hosted && <p className="panel panel--warn" data-testid="not-configured">Sign-in and calls need PVL_AGENT_BASE_URL (the https URL PingFederate can reach for this agent). Reading the Company works without it.</p>}
      <p className="sr-only" role="status" aria-live="polite">{msg}</p>
      {msg && <p className="panel" data-testid="msg">{msg}</p>}
    </>
  );

  const ctx = { info, state, busy, off, scopes, scope, setScope, origin, setOrigin, issuer, setIssuer, path, setPath, useResource, setUseResource, mismatch, as, pickAs, oneClick, discover, signIn, call };
  return (
    <div className="rp">
      {page === 1 && <IntroPage />}
      {page === 2 && <CallsPage ui={notices} c={ctx} />}
      {page === 3 && <TokenPage state={state} />}
      <Pager page={page} pages={PAGES} plainNext={page === 2} onPage={(n) => { setPage(n); window.scrollTo?.({ top: 0 }); }} />
    </div>
  );
}
