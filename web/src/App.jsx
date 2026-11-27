import React, { useCallback, useEffect, lazy, Suspense, useState } from "react";
import fs from "node:fs";
import RunPanel from "./components/RunPanel";
import AtlasChat from "./components/AtlasChat";
import DiagramTab from "./components/DiagramTab";
import VerifyPanel from "./components/VerifyPanel";
import ConsentScreen from "./components/ConsentScreen";
import { getJson, postJson, resetWorkspace } from "./api";
import TopMenu, { applyFontSize } from "./top-menu/TopMenu.jsx";
import TalkTrackDialog from "./talk-track/TalkTrackDialog.jsx";
import talkMd from "../../docs/talk-track.md?raw";
import VerifyMark from "./components/VerifyMark.jsx";
import StoryToggle, { storyKey } from "./story/StoryToggle.jsx";

// Story mode is loaded only when the viewer switches it on, so the page in Demo mode does not pay for it.
const StoryRoot = lazy(() => import("./StoryRoot.jsx"));
export const STORY_PREFIX = "pvl";

// If the Story chunk cannot load (a rebuild, a stale file name, the network) the shell bar must survive: Demo mode is never taken down by Story.
class StoryBoundary extends React.Component {
  constructor(props) { super(props); this.state = { failed: false }; }
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <div className="story-bar" role="alert" data-testid="story-error">
        <span className="story-msg">Story could not load. Reload the page and try again.</span>
        <button type="button" onClick={this.props.onExit}>Exit</button>
      </div>
    );
  }
}

const VERSION = (() => { try { return JSON.parse(fs.readFileSync(new URL("../../package.json", import.meta.url), "utf8")).version || null; } catch { return null; } })();

export const TABS = [
  { id: "verify", label: "Verify" },
  { id: "run", label: "Run it" },
  { id: "chat", label: "Agent chat" },
  { id: "diagram", label: "Diagram" },
  { id: "why", label: "Why this protocol" },
  { id: "talk", label: "Talk track" },
];
// Never blank and never claims a mode before it knows: until /api/info answers (or if it fails) it says both.
export const BANNER_UNKNOWN = "MOCK or REAL: this page is loading. Mock runs against a reference Company and issuer built into this app; Real talks to the Company and issuer you name.";
export const BANNER_FAILED = "MODE UNKNOWN: the page could not read /api/info from its server, so it cannot say whether this is Mock or Real. Every action is off until the server answers.";
const BANNER_REAL = "REAL: this agent talks to the Company and the authorization server you name, and to nothing else. Only the person (a demo user) and the agent are test data.";
const BANNER_MOCK = "MOCK: a reference Company and issuer run inside this app, so nothing leaves this machine. Every token is a mock token, signed by the mock issuer. Switch to Real to test a Company you name.";

const hashTab = () => { const h = window.location.hash.replace("#", ""); return TABS.some((t) => t.id === h) ? h : "verify"; };

const THEME_KEY = "poppy.theme";
function initialTheme() {
  try { const t = localStorage.getItem(THEME_KEY); if (t === "light" || t === "dark") return t; } catch { /* storage blocked */ }
  return "auto";
}

export default function App() {
  const [info, setInfo] = useState(undefined); // undefined = loading, null = failed
  const [talkOpen, setTalkOpen] = useState(false);
  const talkSteps = (() => {
    const steps = []; let n = 0;
    for (const line of talkMd.split("\n")) {
      const m = line.match(/^\d+\.\s+(?:"(.+?)"|\*\*(.+?)\.\*\*\s*(.*))$/);
      if (m) { n += 1; steps.push({ id: `s${n}`, title: (m[1] || m[2]).slice(0, 60), say: m[1] || m[3] }); }
    }
    return steps.length ? steps : [{ id: "s1", title: "Talk track", say: talkMd.slice(0, 600) }];
  })();
  const [vertical, setVertical] = useState("banking");
  const [story, setStory] = useState(null);
  const [tab, setTab] = useState(hashTab());
  // Mock only: the reference issuer's consent page is this screen, reached by /?consent=<id> from the Run it tab.
  const [consentId, setConsentId] = useState(() => { try { return new URLSearchParams(window.location.search).get("consent"); } catch { return null; } });
  const [presenter, setPresenter] = useState(false);
  const [resetSignal, setResetSignal] = useState(0);
  const [resetMsg, setResetMsg] = useState("");
  const [theme, setTheme] = useState(initialTheme);
  const [fontStep, setFontStep] = useState(() => { try { const f = localStorage.getItem("poppy.font"); return ["S", "M", "L"].includes(f) ? f : "M"; } catch { return "M"; } });
  const [storyOn, setStoryOn] = useState(() => { try { return localStorage.getItem(storyKey(STORY_PREFIX)) === "story" || new URLSearchParams(window.location.search).get("story") === "1"; } catch { return false; } });
  const [toggleKey, setToggleKey] = useState(0); // re-mounts the toggle after an in-story Exit so its pressed state follows
  // Exit in the Story bar: back to Demo, remembered, and ?story=1 dropped from the address so a reload stays in Demo.
  const leaveStory = useCallback(() => {
    setStoryOn(false);
    setToggleKey((k) => k + 1);
    try { localStorage.setItem(storyKey(STORY_PREFIX), "demo"); } catch { /* storage blocked: the choice just does not persist */ }
    try { const u = new URL(window.location.href); if (u.searchParams.has("story")) { u.searchParams.delete("story"); window.history.replaceState(null, "", u); } } catch { /* no address to tidy */ }
  }, []);
  useEffect(() => { applyFontSize(fontStep); try { localStorage.setItem("poppy.font", fontStep); } catch { /* storage blocked */ } }, [fontStep]);

  useEffect(() => { if (theme === "auto") delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = theme; }, [theme]);

  const pickTheme = (next) => {
    try { if (next === "auto") localStorage.removeItem(THEME_KEY); else localStorage.setItem(THEME_KEY, next); } catch { /* not remembered */ }
    setTheme(next);
  };

  useEffect(() => { getJson("/api/info").then(setInfo, () => setInfo(null)); }, []);
  useEffect(() => { getJson(`/api/talktrack?vertical=${encodeURIComponent(vertical)}`).then(setStory, () => setStory(null)); }, [vertical]);
  const TALK = story ? story.talkTrack : [];
  useEffect(() => {
    const on = () => setTab(hashTab());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  const select = (id) => { setTab(id); try { window.history.replaceState(null, "", `#${id}`); } catch { /* ignore */ } };

  useEffect(() => {
    const on = (e) => {
      if (e.ctrlKey || e.metaKey || e.altKey) return; // Ctrl/Cmd+P is print, not presenter mode
      if (e.target && /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName)) return;
      if (e.key === "p" || e.key === "P") setPresenter((v) => !v);
      else if (e.key === "Escape") setPresenter(false);
    };
    window.addEventListener("keydown", on);
    return () => window.removeEventListener("keydown", on);
  }, []);

  const reset = useCallback(async () => {
    window.dispatchEvent(new CustomEvent("pv:reset")); // Story mode: a step waiting for a run is told the page was reset
    const ok = await resetWorkspace().catch(() => false);
    setResetSignal((n) => n + 1);
    setResetMsg(ok ? "Reset: your sign-in and step log are cleared and the diagram is back in place." : "Reset failed on the server; the view was reset.");
  }, []);

  const onKeyTab = (e, i) => {
    if (!["ArrowRight", "ArrowLeft", "Home", "End"].includes(e.key)) return;
    e.preventDefault();
    const next = e.key === "Home" ? TABS[0] : e.key === "End" ? TABS[TABS.length - 1] : TABS[(i + (e.key === "ArrowRight" ? 1 : TABS.length - 1)) % TABS.length];
    select(next.id);
    document.getElementById(`tab-${next.id}`)?.focus();
  };

  const hosted = info ? !!info.hosted : null;
  const banner = info === null ? BANNER_FAILED : hosted === true ? BANNER_MOCK : hosted === false ? BANNER_REAL : BANNER_UNKNOWN;
  return (
    <div className={`app${presenter ? " app--presenter" : ""}`}>
      <header className="shell-bar">
        <span className="shell-brand">
          <span className="shell-logo" aria-hidden="true">PV</span>
          <h1>Poppy verification</h1>
          {info?.source === "real"
            ? <span className="shell-badge shell-badge--real" data-testid="mode-badge">Real</span>
            : <span className="shell-badge" data-testid="mode-badge">Mock</span>}
        </span>
        <nav className="shell-nav" aria-label="Sections">
          {TABS.map((t, i) => (
            <a key={t.id} id={`tab-${t.id}`} href={`#${t.id}`} aria-current={tab === t.id ? "page" : undefined}
              onClick={(e) => { e.preventDefault(); select(t.id); }} onKeyDown={(e) => onKeyTab(e, i)}>{t.label}</a>
          ))}
        </nav>
        <TopMenu
          mode={{ value: info?.source === "real" ? "real" : "mock", onChange: async (source) => {
            // postJson sends this browser's X-Workspace, so the mode switch is for this visitor only (rule 13).
            const res = await postJson("/api/mode", { source }).catch(() => null);
            if (res && res.ok) { const i = await getJson("/api/info").catch(() => null); setInfo(i); getJson(`/api/talktrack?vertical=${encodeURIComponent(vertical)}`).then(setStory, () => setStory(null)); }
          }, realAvailable: info ? info.realAvailable === true : false, realHint: info?.realReason }}
          vertical={{ value: vertical, onChange: setVertical, options: story ? story.verticals : ["banking"] }}
          theme={{ value: theme, onChange: pickTheme }}
          fontSize={{ value: fontStep, onChange: setFontStep }}
          present={{ active: presenter, onToggle: () => setPresenter((v) => !v), label: "Presenter (P)" }}
          talkTrack={{ active: talkOpen, onToggle: () => setTalkOpen((v) => !v) }}
          shelfUrl="https://local.ping-devops.com:8443/"
          help={{ href: "https://github.com/curtismu7/poppy-verification-LAB#readme" }}
          version={VERSION}
          onReset={reset}
          extra={<StoryToggle key={toggleKey} prefix={STORY_PREFIX} onChange={setStoryOn} />}
        >
          <VerifyMark id="poppy-verification" />
        </TopMenu>
      </header>
      <main className="page">
        <p className="banner" role="status" data-testid="banner">{banner}</p>
        <p className="sr-only" role="status" aria-live="polite">{resetMsg}</p>
        {!presenter && <p className="intro">Check a Company against the Personal Agent Protocol 1.0: run the conformance suite, or play the personal agent yourself (discover, sign in with a URL as your client id, call the API with a signed Poppy-Session).</p>}
        <div id={`panel-${tab}`}>
          {presenter && tab !== "talk" && (
            <aside className="presenter-say" data-testid="presenter-say" aria-label="Talk track">
              {TALK.filter((t) => (tab === "verify" ? ["say-first", "verify", "why-poppy"] : tab === "run" ? ["say-first", "discover", "signin", "call"] : tab === "chat" ? ["say-first", "why-poppy"] : tab === "why" ? ["why-poppy", "value-company", "value-developer", "value-person", "value-ping"] : ["say-first", "why"]).includes(t.id)).map((t) => <p key={t.id}><strong>{t.title}.</strong> {t.say}</p>)}
            </aside>
          )}
          {consentId && <ConsentScreen id={consentId} onDone={() => setConsentId(null)} />}
          {!consentId && tab === "verify" && <VerifyPanel info={info} />}
          {!consentId && tab === "run" && <RunPanel info={info} resetSignal={resetSignal} />}
          {!consentId && tab === "chat" && <AtlasChat info={info} resetSignal={resetSignal} />}
          {!consentId && tab === "diagram" && <DiagramTab resetSignal={resetSignal} />}
          {tab === "why" && (
            <div className="talk" data-testid="why-poppy">
              {TALK.filter((t) => ["why-poppy", "value-company", "value-developer", "value-person", "value-ping"].includes(t.id)).map((t) => <section key={t.id}><h2>{t.title}</h2><p>{t.say}</p></section>)}
            </div>
          )}
          {tab === "talk" && (
            <div className="talk">{TALK.map((t) => <section key={t.id}><h2>{t.title}</h2><p>{t.say}</p></section>)}</div>
          )}
        </div>
      <TalkTrackDialog isOpen={talkOpen} onClose={() => setTalkOpen(false)} talk={talkSteps} />
      {storyOn ? (
        <StoryBoundary onExit={leaveStory}>
          <Suspense fallback={null}>
            <StoryRoot mode={info?.source === "real" ? "real" : "mock"} ready={info !== undefined} onExit={leaveStory} prefix={STORY_PREFIX} />
          </Suspense>
        </StoryBoundary>
      ) : null}

      </main>
    </div>
  );
}
