import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';

const sourceRoots = ['components', 'engine'];
const sourceExtensions = new Set(['.ts', '.tsx']);
const secretPatterns = [
  /AIza[0-9A-Za-z_-]{20,}/,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
];

async function walk(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await walk(path));
    else if (sourceExtensions.has(entry.name.slice(entry.name.lastIndexOf('.')))) files.push(path);
  }
  return files;
}

const files = (await Promise.all(sourceRoots.map(walk))).flat();
assert.ok(files.length > 0, 'lint found no TypeScript source files');
for (const file of files) {
  const source = await readFile(file, 'utf8');
  assert.equal(source.includes('\u0000'), false, `${file}: contains a NUL byte`);
  for (const pattern of secretPatterns) assert.equal(pattern.test(source), false, `${file}: possible secret material`);
}
console.log(`lint: inspected ${files.length} TypeScript source files`);