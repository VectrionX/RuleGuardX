import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

test('package exposes reproducible quality gates', async () => {
  const pkg = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
  for (const script of ['build', 'lint', 'typecheck', 'test', 'ci']) assert.ok(pkg.scripts[script]);
  assert.equal(pkg.private, true);
});

test('offline analyzer remains present and browser-only', async () => {
  const analyzer = await readFile(new URL('../engine/analyzer.ts', import.meta.url), 'utf8');
  assert.match(analyzer, /export const analyzeRules/);
  assert.doesNotMatch(analyzer, /fetch\s*\(/);
});