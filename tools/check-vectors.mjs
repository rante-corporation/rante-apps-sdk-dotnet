// Checks the conformance vectors of Rante.Apps.Packaging against the reference CLI in rante-apps-sdk, so the C# port
// and the JavaScript CLI provably apply the same rules.
//   node tools/check-vectors.mjs <path to a checkout of rante-corporation/rante-apps-sdk>
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const reference = path.resolve(process.argv[2] || 'reference');
const require = createRequire(import.meta.url);
const { checkPath } = require(path.join(reference, 'packages', 'cli', 'lib', 'paths.js'));
const { validateManifest } = require(path.join(reference, 'packages', 'cli', 'lib', 'manifest.js'));
const { parseManifestBytes } = require(path.join(reference, 'packages', 'cli', 'lib', 'package.js'));

const here = path.dirname(fileURLToPath(import.meta.url));
const vectors = path.join(here, '..', 'tests', 'Rante.Apps.Packaging.Tests', 'conformance');
const read = (name) => JSON.parse(readFileSync(path.join(vectors, name), 'utf8'));

/** {s*N} repeats s N times; {U+XXXX} is that character. */
function expand(value) {
  if (typeof value === 'string') {
    return value
      .replace(/\{U\+([0-9A-Fa-f]{4,6})\}/g, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
      .replace(/\{([^*}]+)\*(\d+)\}/g, (_, text, count) => text.repeat(Number(count)));
  }
  if (Array.isArray(value)) return value.map(expand);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, expand(v)]));
  return value;
}

const failures = [];
const fail = (what, expected, actual) => failures.push(`${what}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);

const paths = read('paths.json');
for (const c of paths.cases) {
  const input = expand(c.path);
  const result = checkPath(input);
  const code = result.ok ? null : result.code;
  if (code !== c.code) fail(`path ${JSON.stringify(c.path)}`, c.code, code);
  if (result.ok && c.normalized !== undefined) {
    if (result.path !== expand(c.normalized)) fail(`path ${JSON.stringify(c.path)} normalized`, expand(c.normalized), result.path);
    if (result.isDirectory !== c.isDirectory) fail(`path ${JSON.stringify(c.path)} isDirectory`, c.isDirectory, result.isDirectory);
  }
}

const manifests = read('manifests.json');
for (const c of manifests.cases) {
  let manifest;
  if (Object.prototype.hasOwnProperty.call(c, 'manifest')) {
    manifest = expand(c.manifest);
  } else {
    manifest = expand(structuredClone(manifests.base[c.base]));
    for (const [k, v] of Object.entries(expand(c.set || {}))) {
      if (v === null) delete manifest[k];
      else manifest[k] = v;
    }
  }
  const fields = validateManifest(manifest).map((e) => e.field).sort();
  const expected = c.fields.slice().sort();
  if (JSON.stringify(fields) !== JSON.stringify(expected)) fail(`manifest "${c.name}"`, expected, fields);
}

for (const c of manifests.raw) {
  let bytes;
  if (c.hex !== undefined) bytes = Buffer.from(c.hex, 'hex');
  else if (c.bom !== undefined) bytes = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(manifests.base[c.bom]))]);
  else bytes = Buffer.from(c.text, 'utf8');
  const parsed = parseManifestBytes(bytes);
  const code = parsed.errors.length ? parsed.errors[0].code : null;
  if (code !== c.code) fail(`raw "${c.name}"`, c.code, code);
  if (c.bom !== undefined && !parsed.warnings.some((w) => w.code === 'manifest_bom')) fail(`raw "${c.name}" warning`, 'manifest_bom', parsed.warnings);
}

const total = paths.cases.length + manifests.cases.length + manifests.raw.length;
if (failures.length > 0) {
  console.error(`${failures.length} of ${total} vectors disagree with the reference CLI:`);
  for (const f of failures) console.error(`  ${f}`);
  process.exit(1);
}
console.log(`All ${total} vectors agree with the reference CLI (${reference}).`);
