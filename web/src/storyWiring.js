// Story wiring: the lab's own glue between the shared Story engine (web/src/story/, vendored) and this page. It turns the script (storyScript.js) into engine
// steps and gives the engine a `host` that reads and drives the page: the tabs, the Run it buttons, the run events. It never edits the page's own markup; it
// clicks the page's own buttons with script-made events (isTrusted is false, so Play for me is not mistaken for the viewer's own input).
//
// The page announces runs with pv:run-start and pv:run-end ({ ok }): ok is false only when the request itself failed. A verification run that finds failures
// completes normally (the failures are in the report), so it is a run that ended ok.

import { STEPS, VERIFY_DEFECT } from './storyScript.js';

const text = (el) => (el && el.textContent ? el.textContent.trim() : '');

export function createHost({ win = window, doc = document, mode = () => 'mock', settleMs = 400 } = {}) {
  const runs = { starts: 0, ends: 0, lastOk: true };
  const waiters = new Set();
  const timers = new Set();
  const watchers = new Set();
  const onStart = () => { runs.starts += 1; watchers.forEach((f) => f()); };
  const onEnd = (e) => {
    runs.ends += 1; runs.lastOk = e.detail ? e.detail.ok !== false : true;
    for (const w of [...waiters]) w(runs.lastOk);
    watchers.forEach((f) => f());
  };
  // A Reset clears the page's state: a step waiting for a run is told so (and the run's own end, which follows, finds nobody waiting).
  const onReset = () => { for (const w of [...waiters]) w(false, 'The page was reset. Press Next to carry on, or Exit.'); };
  win.addEventListener('pv:run-start', onStart);
  win.addEventListener('pv:run-end', onEnd);
  win.addEventListener('pv:reset', onReset);

  const q = (sel) => doc.querySelector(sel);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const click = (el) => { if (!el || el.disabled) throw new Error('the button is not available'); el.click(); };

  return {
    mode,
    query: q,
    mark: () => ({ starts: runs.starts, ends: runs.ends }),
    runStarted: (m) => runs.starts > m.starts,
    runInFlight: () => runs.starts > runs.ends,
    onRun: (cb) => { watchers.add(cb); return () => watchers.delete(cb); },
    waitForRun(m, timeoutMs) {
      return new Promise((resolve) => {
        const finish = (r) => { clearTimeout(t); timers.delete(t); waiters.delete(check); resolve(r); };
        const done = (ok, reason) => finish(ok ? { ok: true } : { ok: false, reason: reason || 'The run failed. Press Next to carry on, or Exit.' });
        const check = (ok, reason) => { if (reason || runs.ends > m.ends) done(ok, reason); };
        const t = setTimeout(() => finish({ ok: false, reason: 'The run did not finish in time. Press Next to carry on, or Exit.' }), timeoutMs);
        timers.add(t);
        if (runs.ends > m.ends) { done(runs.lastOk); return; }
        waiters.add(check);
      });
    },
    prefill(step) {
      if (!step.prompt || !step.prompt.text) return;   // this lab prompts by pressing an existing button, not by typing
    },
    send(step) {
      if (step.prompt && step.prompt.press) { click(q(step.prompt.press)); return; }
      throw new Error('the step has no button to press');
    },
    switchTab(tab) {
      const el = q(`#tab-${tab}`);
      if (el && el.getAttribute('aria-current') !== 'page') el.click();
    },
    assetUrl: () => null,   // no screenshot ships; a slide is text-only
    dispose() { win.removeEventListener('pv:run-start', onStart); win.removeEventListener('pv:run-end', onEnd); win.removeEventListener('pv:reset', onReset); timers.forEach(clearTimeout); timers.clear(); waiters.clear(); watchers.clear(); },
    _sleep: sleep, _settleMs: settleMs,
  };
}

// ---- finding what a bubble points at. A target that is not on the page skips the step, so a bubble never claims something the page does not show.
const rowById = (doc, id) => doc.querySelector(`[data-testid=row-${id}]`) || null;
const rowByKind = (kind) => (doc) => rowById(doc, kind);
// The row ids the call list uses; there is no "discover" row — discovery is the poppy.json + protected-resource pair.
const KIND_TO_ROW = { discover: 'poppy', par: 'par', authorize: 'authorize', token: 'token', call: 'call' };

function targetFor(doc, t) {
  if (!t) return null;
  if (typeof t === 'string') return t;
  if (typeof t === 'function') return () => t(doc);
  return null;
}

const targetForKind = (kind) => () => rowById(document, KIND_TO_ROW[kind] ?? kind);

// ---- the live fact lines a bubble shows (read from the page, never invented)
function linesFor(doc, step) {
  switch (step.lines) {
    case 'callStatus': return () => { const el = rowById(doc, 'call'); if (!el) return []; const s = el.querySelector('.rp-status'); return s ? [`the call answered: ${text(s)}`] : []; };
    case 'summary': return () => { const el = doc.querySelector('[data-testid=verify-summary] .vf-verdict'); return el ? [text(el)] : []; };
    case 'defectRow': return () => {
      const el = doc.querySelector('[data-testid=verify-summary] .vf-verdict');
      const row = doc.querySelector('[data-testid=check-as-protected-resources]');
      const out = [];
      if (row) out.push(`${text(row.querySelector('.vf-title'))}: ${text(row.querySelector('.vf-chip'))} — ${text(row.querySelector('.vf-detail'))}`.slice(0, 220));
      if (el) out.push(text(el));
      return out;
    };
    default: return undefined;
  }
}

// ---- conditions
const CONDITIONS = {
  // The defect tick-boxes only exist in Mock (Real reads a real Company and has nothing to break).
  mockVerify: (doc) => () => !!doc.querySelector('[data-testid=verify-mock]'),
  // The observability bubble needs something to point at: at least one call row with a status.
  hasRun: (doc) => () => !!doc.querySelector('.rp-calls .rp-status--ok, .rp-calls .rp-status--warn'),
  // The sign-in redirect reloads the page and the story restarts; when the one-click run already landed (rows carry statuses),
  // the intro slides and the "press Run it" prompt are skipped and the story walks the rows that are already there.
  hasNotRun: (doc) => () => !doc.querySelector('.rp-calls .rp-status--ok, .rp-calls .rp-status--warn'),
};

export const NOT_YET = [];

/** The script as engine steps. */
export function buildSteps({ host, doc = document, win = window, script = STEPS, notYet = NOT_YET }) {
  let tab;
  return script.filter((s) => !notYet.includes(s.key)).map((s) => {
    if (s.tab) tab = s.tab;
    const step = { key: s.key, type: s.type, trigger: s.trigger, modes: s.modes, sampleKey: s.sampleKey, prefer: s.prefer, tab };
    if (s.prompt) step.prompt = s.prompt;
    if (s.when) step.when = CONDITIONS[s.when](doc);
    if (s.type === 'bubble') {
      step.target = s.targetKind ? targetForKind(s.targetKind) : targetFor(doc, s.target);
      // The Run tab opens on its intro page; the "Run it (1 click)" button lives on the calls page. Open it first (the pager dot, labelled "Page 2 of 3").
      // The defect tick-boxes live in a closed <details>; open it before the defect step's press.
      if (s.key === 'verify_defect') {
        step.before = async () => {
          const d = doc.querySelector('[data-testid=verify-mock] details');
          if (d && !d.open) { d.open = true; await host._sleep(200); }
        };
      }
      if (s.key === 'run_one_click' || s.key === 'run_intro') {
        step.before = async () => {
          const dot = [...doc.querySelectorAll('.pager__dot')].find((b) => (b.getAttribute('aria-label') || '').startsWith('Page 2 '));
          if (dot && doc.querySelector('[data-testid=one-click]') === null) dot.click();
          if (doc.querySelector('[data-testid=one-click]') === null) { await host._sleep(200); }
        };
      }
      const lines = linesFor(doc, s);
      if (lines) step.lines = lines;
    }
    return step;
  });
}
