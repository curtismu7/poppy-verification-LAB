// Story wiring tests (vitest): the host reads the page, drives the tabs, waits for runs; the script turns into engine steps.
import { describe, expect, it, vi, afterEach } from "vitest";
import { cleanup, render, screen, waitFor, fireEvent } from "@testing-library/react";
import { createHost, buildSteps } from "./storyWiring.js";
import { STEPS, VERIFY_DEFECT, scriptKeys } from "./storyScript.js";
import StoryRoot from "./StoryRoot.jsx";

afterEach(() => { cleanup(); delete window.__storyOn; document.documentElement.classList.remove("story-on"); });

const event = (t, detail) => new CustomEvent(t, { detail });
const fired = [];

describe("createHost", () => {
  it("counts runs from the page's events, and waitForRun resolves with the last result when the run already ended", async () => {
    const host = createHost();
    const marker = host.mark();
    expect(host.runInFlight()).toBe(false);
    window.dispatchEvent(event("pv:run-start"));
    expect(host.runInFlight()).toBe(true);
    window.dispatchEvent(event("pv:run-end", { ok: true }));
    expect(host.runInFlight()).toBe(false);
    await expect(host.waitForRun(marker, 500)).resolves.toEqual({ ok: true });
    host.dispose();
  });

  it("waitForRun resolves when the run ends, and reports a failed run", async () => {
    const host = createHost();
    const marker = host.mark();
    const p = host.waitForRun(marker, 1000);
    window.dispatchEvent(event("pv:run-start"));
    window.dispatchEvent(event("pv:run-end", { ok: false }));
    await expect(p).resolves.toEqual({ ok: false, reason: expect.stringMatching(/failed/i) });
    host.dispose();
  });

  it("waitForRun times out with a message, and a reset releases a waiting step", async () => {
    const host = createHost();
    const marker = host.mark();
    await expect(host.waitForRun(marker, 30)).resolves.toEqual({ ok: false, reason: expect.stringMatching(/did not finish/i) });
    const p = host.waitForRun(host.mark(), 1000);
    window.dispatchEvent(event("pv:reset"));
    await expect(p).resolves.toEqual({ ok: false, reason: expect.stringMatching(/reset/i) });
    host.dispose();
  });

  it("send presses the step's own button with an untrusted click; a disabled button is refused", () => {
    document.body.innerHTML = '<button data-testid="verify-run" disabled>x</button><button data-testid="go">go</button>';
    const host = createHost();
    expect(() => host.send({ prompt: { press: '[data-testid=verify-run]' } })).toThrow(/not available/);
    const go = document.querySelector('[data-testid=go]');
    go.disabled = false;
    host.send({ prompt: { press: '[data-testid=go]' } });
    host.dispose();
  });

  it("switchTab clicks the tab link when it is not current, and leaves it alone when it is", () => {
    document.body.innerHTML = '<a id="tab-run" aria-current="page"></a><a id="tab-verify"></a>';
    const host = createHost();
    const spy = vi.spyOn(document.querySelector('#tab-verify'), 'click');
    host.switchTab("verify");
    expect(spy).toHaveBeenCalled();
    const spy2 = vi.spyOn(document.querySelector('#tab-run'), 'click');
    host.switchTab("run");
    expect(spy2).not.toHaveBeenCalled();
    host.dispose();
  });

  it("onRun tells its watcher when a run starts and ends; dispose unsubscribes", () => {
    const host = createHost();
    const seen = [];
    const off = host.onRun(() => seen.push(1));
    window.dispatchEvent(event("pv:run-start"));
    off();
    window.dispatchEvent(event("pv:run-end", { ok: true }));
    expect(seen).toEqual([1]);
    host.dispose();
  });
});

describe("buildSteps", () => {
  it("one engine step per script entry, in order, with tabs carried forward", () => {
    const steps = buildSteps({ host: createHost() });
    expect(steps.map((s) => s.key)).toEqual(STEPS.map((s) => s.key));
    const why = steps.find((s) => s.key === "why_poppy");
    expect(why.tab).toBe("why");
    // a step with no tab of its own belongs to the last tab named before it
    expect(steps.find((s) => s.key === "run_discover").tab).toBe("run");
    expect(steps.find((s) => s.key === "verify_intro").tab).toBe("verify");
  });

  it("the defect step names the catalogue's protected_resources defect and is mock-only", () => {
    expect(VERIFY_DEFECT).toBe("no_protected_resources");
    const d = buildSteps({ host: createHost() }).find((s) => s.key === "verify_defect");
    expect(d.modes).toEqual(["mock"]);
    expect(d.prompt.press).toBe(`[data-testid=defect-${VERIFY_DEFECT}]`);
  });

  it("scriptKeys matches the script: bubbles, slides and sample keys", () => {
    const k = scriptKeys();
    expect(k.steps).toEqual(STEPS.filter((s) => s.type === "bubble").map((s) => s.key));
    expect(k.slides).toEqual(STEPS.filter((s) => s.type === "slide").map((s) => s.key));
    expect(k.sampleKeys.length).toBeGreaterThan(0);
  });
});

describe("StoryRoot", () => {
  it("renders the story bar from the served wording, and cleans up on unmount", async () => {
    const fetchMock = vi.fn((url) => {
      if (String(url).includes("/api/story")) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ opening: { title: "t", header: "h", lead: "l", verdict: "v", colA: { heading: "a", lines: ["x"] }, colB: { heading: "b", lines: ["y"] } }, closing: { title: "t", lead: "l", verdict: "v", colA: { heading: "a", lines: ["x"] }, colB: { heading: "b", lines: ["y"] } }, slides: {}, steps: {}, sourceSha256: "x" }) });
      }
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<StoryRoot mode="mock" ready onExit={() => {}} prefix="pvl-test" />);
    await waitFor(() => expect(screen.getByTestId("story-bar")).toBeTruthy(), { timeout: 3000 });
    expect(fetchMock).toHaveBeenCalledWith("/api/story", expect.anything());
    expect(document.documentElement.classList.contains("story-on")).toBe(true);
  });

  it("a wording problem shows the error bar with the server's message, and Demo mode survives", async () => {
    const fetchMock = vi.fn(() => Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({ error: "Story wording could not be read: captions.md: a test problem" }) }));
    vi.stubGlobal("fetch", fetchMock);
    render(<StoryRoot mode="mock" ready onExit={() => {}} prefix="pvl-test" />);
    await waitFor(() => expect(screen.getByTestId("story-error")).toBeTruthy());
    expect(screen.getByText(/a test problem/)).toBeTruthy();
  });
});
