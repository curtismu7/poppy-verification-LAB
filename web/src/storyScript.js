// The Story script: one entry per caption key, in the order the walk-through shows them. Pure data, no DOM: storyWiring.js turns each entry into an engine
// step (a selector, a live line). The wording is in video/captions.md; test/story.test.js checks the two agree.
//
//   target   a CSS selector | () => Element|null (missing at show time => the step is skipped)
//   prompt   { press } the viewer (or Play) presses that existing button
//   lines    the name of a live value the page reads for the bubble's fact lines (storyWiring.js)
//   when     the name of a condition (storyWiring.js CONDITIONS)
//   modes    ['real'] or ['mock']: shown only there. sampleKey: the Mock wording key.
//   tab      switch to this tab before the step shows
// Hold times for Play for me come from the wording and the shared hold.js — no fixed holds (no video to match yet).

export const VERIFY_DEFECT = 'no_protected_resources';

const VERIFY = 'verify';
const RUN = 'run';

export const STEPS = [
  { key: 'mock_note', type: 'slide', trigger: 'load', modes: ['mock'] },   // the simulated run says so first
  { key: 'opening', type: 'slide', trigger: 'load' },
  { key: 'why_poppy', type: 'slide', trigger: 'load', tab: 'why', when: 'hasNotRun' },

  // ---- the Run tab: the story presses "Run it (1 click)" (walk.py --send run_one_click), then the bubbles land on the
  // rows the run produced. A row that this run did not produce skips its bubble (an unconfigured Real lab, a Company without PAR).
  { key: 'run_intro', type: 'bubble', tab: RUN, trigger: 'load', target: '#rp-calls', prefer: 'below', when: 'hasNotRun' },
  { key: 'run_one_click', type: 'bubble', tab: RUN, trigger: 'load', target: '[data-testid=one-click]', prefer: 'above', when: 'hasNotRun', prompt: { press: '[data-testid=one-click]' } },
  { key: 'run_discover', type: 'bubble', trigger: 'run-done', targetKind: 'poppy', prefer: 'below' },
  { key: 'run_par', type: 'bubble', trigger: 'run-done', targetKind: 'par', prefer: 'below', sampleKey: 'sample_run_par' },
  { key: 'run_authorize', type: 'bubble', trigger: 'run-done', targetKind: 'authorize', prefer: 'below' },
  { key: 'run_token', type: 'bubble', trigger: 'run-done', targetKind: 'token', prefer: 'below', sampleKey: 'sample_run_token' },
  { key: 'run_call', type: 'bubble', trigger: 'run-done', targetKind: 'call', prefer: 'below', sampleKey: 'sample_run_call' },
  { key: 'run_done', type: 'bubble', trigger: 'run-done', target: () => document.querySelector('.rp-calls'), prefer: 'below' },
  { key: 'run_unconfigured', type: 'bubble', trigger: 'load', target: '[data-testid=not-configured]', prefer: 'below', modes: ['real'] },

  // ---- the Verify tab: run the suite, then catch a defect
  { key: 'verify_intro', type: 'bubble', tab: VERIFY, trigger: 'load', target: '[data-testid=verify-panel] h2', prefer: 'below' },
  { key: 'verify_run', type: 'bubble', trigger: 'load', target: '[data-testid=verify-run]', prefer: 'above', prompt: { press: '[data-testid=verify-run]' }, sampleKey: 'sample_verify_run' },
  { key: 'verify_all_pass', type: 'bubble', trigger: 'run-done', target: '[data-testid=verify-summary] .vf-verdict--ok', prefer: 'below', lines: 'summary' },
  { key: 'verify_defect', type: 'bubble', trigger: 'load', target: `[data-testid=defect-${VERIFY_DEFECT}]`, prefer: 'above', modes: ['mock'], when: 'mockVerify', prompt: { press: `[data-testid=defect-${VERIFY_DEFECT}]` } },
  { key: 'verify_run2', type: 'bubble', trigger: 'load', target: '[data-testid=verify-run]', prefer: 'above', prompt: { press: '[data-testid=verify-run]' }, modes: ['mock'], sampleKey: 'sample_verify_run' },
  { key: 'verify_defect_caught', type: 'bubble', trigger: 'run-done', target: '[data-testid=verify-summary] .vf-verdict--bad', prefer: 'below', modes: ['mock'], lines: 'defectRow' },

  // ---- what the run left behind (skipped when the lab has no record)
// ---- what a run leaves behind: this lab keeps its trail in the Run tab's call rows and the Verify report, which the earlier
// bubbles already point at, so the observability bubble is a plain point at the calls list (skipped when nothing has run yet).
  { key: 'observability', type: 'bubble', trigger: 'load', target: () => document.querySelector('.rp-calls'), prefer: 'below', sampleKey: 'sample_observability', when: 'hasRun' },

  // ---- the end
  { key: 'closing', type: 'slide', trigger: 'load' },
];

// Mock wording keys the script names that are not steps of their own. The unused ones are placeholder names: this lab's clean-run bubbles share one
// wording in Mock (nothing in them claims a live result), so they keep the live key in Mock too — only the bubbles that name a wire action get sample_* wording.
export const EXTRA_SAMPLE_KEYS = [];

// Story-only bubbles (none: this lab has no video, so every key is live in Story).
export const STORY_ONLY = [];
export const VIDEO_ONLY = [];

// What the parity test hands to captions.js parity(): the caption keys this script needs.
export function scriptKeys() {
  return {
    steps: STEPS.filter((s) => s.type === 'bubble').map((s) => s.key),
    slides: STEPS.filter((s) => s.type === 'slide').map((s) => s.key),
    sampleKeys: [...STEPS.map((s) => s.sampleKey).filter(Boolean), ...EXTRA_SAMPLE_KEYS],
  };
}
