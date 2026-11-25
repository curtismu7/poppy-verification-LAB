# Story mode spec (poppy-verification-LAB)

**Status:** draft   **Owner:** Curtis
**Process tier:** 2 (colleagues demo these labs).
**Contract:** `AI-DEMO-Standalone/shared/story/README.md` (merged, PR #553 era; pin 5213603f… era). Runbook: `ADDING-TO-A-LAB.md`. This lab has **no recorded video**, so `captions.md` is written for Story alone (runbook §0) and lives at `video/captions.md`.

## Goal
Give the lab a **Demo | Story** toggle: Demo is the page exactly as it is now; Story walks the viewer through the lab with numbered pop-up bubbles and text slides — Discover, sign in (PAR, CIMD, PKCE, consent), the signed call with token + Poppy-Session, then the Verify tab (the 107-check suite, a defect on, the suite catching it), Why Poppy, and the observability of what a run leaves behind. Works in Mock (fully offline, labelled simulated) and Real.

## Design (per the contract and runbook)
- Vendored `shared/story/` byte-for-byte into `web/src/story/` and `server/src/story/`, pinned by `web/src/story/story.sha256`, checked by `scripts/story-checkPin.mjs` (vendored, unedited) from a test.
- Wording: `video/captions.md`, served at `GET /api/story` — the path the family's tools (walk.py) expect (new server glue `server/src/storyRoute.js`, parser `server/src/story/captions.js`, re-read on change, 500 names a wording problem, never a server path, response carries `sourceSha256`). The **existing** `/api/story` (talk-track data) moves to `/api/talktrack`; its consumers (`App.jsx`, tests) are updated in the same PR.
- Script `web/src/storyScript.js` (pure data, one entry per caption key, trigger `load`/`run-done`), wiring `web/src/storyWiring.js` + `StoryRoot.jsx` copied from the A2A lab and cut down: tabs (`#tab-verify` etc.), no pop-outs (this lab has none), no prompt steps (actions are buttons: `prompt: { press }` where Play for me should press).
- The page announces runs: `pv:run-start` / `pv:run-end` (`detail.ok`) in `VerifyPanel.jsx` (the suite run) and `RunPanel.jsx` (discover / one-click / call). Host hooks `runInFlight` / `onRun` copied from the A2A lab.
- Toggle in `App.jsx`'s TopMenu `extra` slot (alongside VerifyMark); lazy `React.lazy` StoryRoot; `?story=1` and localStorage; Esc exits and drops the query param. `story-on` class on `<html>`.
- Rule 29: the Opening Slide and the Mock-note slide both carry `## Header`.

## Walk-through shape (one mode, one story)
1. Opening slide (Header: "Poppy, verified against the spec").
2. Why-tab slide (why Poppy exists — condensed from TALK_TRACK).
3. Run tab: intro bubble → press "Run it (1 click)" → bubbles per landed row (PAR, authorize, token, call with decoded Poppy-Session) → token-page bubble.
4. Verify tab: run the suite (all pass) → switch a defect (protected_resources) → run again → the named check fails.
5. Observability bubble on the lab's own run records (skipped when empty).
6. Closing slide.

## Acceptance criteria (each a runnable check)
1. Story off: `npm test` unchanged-green; a test asserts the page shows no overlay and no story bar.
2. Pin test passes; an edited vendored file fails it.
3. Parity test both ways; a mismatch fails the build.
4. Mock, offline: the full story walks; every `sample_*` wording says simulated; a test asserts no fetch leaves the lab's origin.
5. Mock walk: Run tab rows appear after the one-click run; Verify passes (107), then fails exactly the named check with the defect on — each bubble gated on the page's own state.
6. Real: the walk runs against a configured Company; steps needing sign-in skip honestly when unconfigured.
7. Play for me: reaches the same end state as Next; stops on manual input; never runs in Demo; at Normal speed holds equal `hold.js` (hold test); Pause freezes/resumes; speeds persist.
8. Browser check 1920x1080 and 1800x1169, Mock and Real (or the PR says which was not walked): `tools/walk.py` exit 0, screenshots read; `tools/play.py` exit 0.
9. `npm run build -w web` and the Docker build still pass; the image contains `video/captions.md`.
10. Public-safe wording: no internal hostnames/ids; the existing host-scan test style covers captions.md.

## Unhappy paths (each needs a check)
- Target missing (no run yet, defect not on, panel empty): step skipped silently, counter adjusts.
- Run fails (502 from a typed Company): story shows the failure honestly, never claims success.
- Viewer clicks Run early / reloads mid-story / presses Back during a run: host `runInFlight`/`onRun` re-sync; Play never double-sends.
- `captions.md` broken: `GET /api/story` 500 names the problem; the page shows the story-error bar, Demo survives.
- localStorage blocked: toggle still works for the session.
- Esc while typing in an input: only exits Story (StoryBar handler), no crash.

## Out of scope
Recorded video / `take.py` (none exists); edits to shared TopMenu or any `shared/` code; Real-mode tenant writes; the agent chat tab's live Claude path; content-pack/talk-track changes beyond the route move.

## Protected / must not break
The existing `/api/story` consumers (talk track, presenter view, content pack); the Verify suite's 107 checks and defect catalogue tests; Mock offline guarantee (no sockets); rule-19 toggle; vendored pins (TopMenu, standalone-ui, JsonPane); port 7821; no new hosts entries.

## Verification plan
- Unit/parity/pin tests locally and on the Air (`air-test`); `npm test` full.
- Playwright: toggle, full Mock walk at both sizes, defect bubble, Play for me, Esc; screenshots read (rule 9). Real walk if the owner's PF is reachable, else said plainly in the PR.
- `/code-review` on the diff; PR waits for the owner's "merge N". Merge → pin bump in AI-DEMO-Standalone → lab-proxy address re-proven.
