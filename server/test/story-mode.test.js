// Story mode tests for poppy-verification-LAB (node:test, server side). The pin, the parity, the public-safe wording and the route.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

import { loadCaptions, loadCaptionsWithHash, resetCaptionsCache, storyResponse, CAPTIONS_PATH } from '../src/storyRoute.js';
import { parity } from '../src/story/captions.js';
import { checkPin } from '../../scripts/story-checkPin.mjs';
import { STEPS, STORY_ONLY, VIDEO_ONLY, scriptKeys } from '../../web/src/storyScript.js';

const root = fileURLToPath(new URL('../..', import.meta.url));

test('story: the vendored Story files match their pin (an edited copy fails CI)', () => {
  assert.deepEqual(checkPin(root), []);
});

test('story: every caption key has a step in the script and every step has wording (the parity test)', () => {
  assert.deepEqual(parity(loadCaptions(), scriptKeys(), { allowUnused: VIDEO_ONLY }), []);
});

test('story: the parity check really fails when the wording and the script drift', () => {
  const captions = loadCaptions();
  const missingWording = { ...captions, steps: Object.fromEntries(Object.entries(captions.steps).filter(([k]) => k !== 'run_call')) };
  assert.deepEqual(parity(missingWording, scriptKeys(), { allowUnused: VIDEO_ONLY }), ['the demo has step "run_call" but captions.md does not']);
  const extra = { ...scriptKeys(), steps: [...scriptKeys().steps, 'brand_new'] };
  assert.deepEqual(parity(captions, extra, { allowUnused: VIDEO_ONLY }), ['the demo has step "brand_new" but captions.md does not']);
});

test('story: the opening slide and the Mock note both carry the rule-29 header', () => {
  const captions = loadCaptions();
  assert.ok(captions.opening.header, 'the Opening Slide has a ## Header naming what the demo shows');
  assert.equal(captions.slides.mock_note?.title, 'Simulated run');
  const raw = fs.readFileSync(CAPTIONS_PATH, 'utf8');
  const note = raw.split('---').find((s) => s.includes('# Slide: mock_note'));
  assert.ok(note && /## Header\n([^\n]+)/.test(note), 'the Mock-note slide has a ## Header (whatever a mode shows first carries the rule-29 title)');
  assert.equal(note.match(/## Header\n([^\n]+)/)[1].trim(), captions.opening.header);
});

test('story: the wording is public-safe: no real host, no tenant or client id, no key material', () => {
  const text = fs.readFileSync(CAPTIONS_PATH, 'utf8');
  const hosts = [...text.matchAll(/https?:\/\/[^\s"'<>)]+/g)].map((m) => m[0]);
  for (const h of hosts) assert.match(h, /\.example\b|\.invalid\b/, `only .example/.invalid hosts, found ${h}`);
  assert.ok(!/\b(ey[Jbeg][A-Za-z0-9_-]{10,})/.test(text), 'no JWT-looking string');
  assert.ok(!/sk[-_][A-Za-z0-9]{8,}/.test(text), 'no key-looking string');
});

test('story: the bubbles come in the same order as the captions keys, and the mode flags sit on the right steps', () => {
  const bubbleKeys = STEPS.filter((s) => s.type === 'bubble').map((s) => s.key);
  const captionKeys = Object.keys(loadCaptions().steps).filter((k) => !k.startsWith('sample_'));
  assert.deepEqual(bubbleKeys, captionKeys);
  const realOnly = STEPS.filter((s) => s.modes?.includes('real') && !s.modes.includes('mock')).map((s) => s.key);
  assert.deepEqual(realOnly, ['run_unconfigured']);
  const mockOnly = STEPS.filter((s) => s.modes?.includes('mock') && !s.modes.includes('real')).map((s) => s.key);
  assert.deepEqual(mockOnly, ['mock_note', 'verify_defect', 'verify_run2', 'verify_defect_caught']);
});

test('story: no fixed holds (no recorded video to match), so Play for me times every bubble from the shared formula', () => {
  for (const s of STEPS) assert.equal(s.fixedSecs, undefined, `${s.key} has no fixedSecs`);
});

test('story: the defects the story names exist in the catalogue, and the defect step is mock-only', () => {
  const captions = loadCaptions();
  const defectName = /Tick the defect that leaves protected_resources out/.test(captions.steps.verify_defect.text);
  assert.ok(defectName, 'the wording names the protected_resources defect');
  assert.deepEqual(STEPS.filter((s) => s.key === 'verify_defect').map((s) => s.modes), [['mock']]);
});

test('story: the route serves the wording, a broken file is a 500 that names the problem and never a server path, and an edit shows without a restart', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pvl-story-'));
  const file = path.join(dir, 'captions.md');
  const clean = fs.readFileSync(CAPTIONS_PATH, 'utf8');
  fs.writeFileSync(file, clean);
  const { status, body } = storyResponse(file);
  assert.equal(status, 200);
  assert.ok(body.sourceSha256, 'the route returns the hash of the bytes it parsed');
  assert.equal(body.sourceSha256, createHash('sha256').update(clean).digest('hex'));
  assert.ok(body.steps.run_call, 'the wording holds the step the script asks for');

  fs.writeFileSync(file, clean + '\n---\n\n# Slide: broken\n\n## NotAField\nx');
  const broken = storyResponse(file);
  assert.equal(broken.status, 500);
  assert.ok(!broken.body.error.includes(dir), 'no server path in the error');
  assert.match(broken.body.error, /captions\.md/, 'the error names the wording problem');

  fs.writeFileSync(file, clean);
  assert.equal(storyResponse(file).status, 200);
  // a captured server path is never sent even when the file is missing
  const missing = storyResponse(path.join(dir, 'nope.md'));
  assert.equal(missing.status, 500);
  assert.ok(!missing.body.error.includes(dir));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('story: the wording file the server reads is the tracked one (loadCaptionsWithHash caches by hash, an edit shows on the next read)', () => {
  resetCaptionsCache();
  const a = loadCaptionsWithHash();
  const b = loadCaptionsWithHash();
  assert.equal(a.sha256, b.sha256);
  resetCaptionsCache();
});
