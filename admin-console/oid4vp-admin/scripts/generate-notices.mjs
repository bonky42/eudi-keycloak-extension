// Renders the third-party attribution file that ships inside the console JAR.
//
// The bundle vite produces inlines its dependencies — PatternFly, React, and the Red Hat fonts
// Keycloak's own account UI carries — so the JAR distributes them while this repository does not:
// node_modules and dist are both ignored, and only package.json and pnpm-lock.yaml are tracked.
// The obligation therefore attaches to the artefact, which is why this is generated at build time
// rather than written by hand and left to rot.
//
// Reads `pnpm licenses list --prod --json` on stdin. Production dependencies only: devDependencies
// (vite, typescript, the build tooling) never reach the bundle.
import { mkdirSync, writeFileSync } from 'node:fs';

const raw = await new Promise((resolve, reject) => {
  let buffer = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', chunk => { buffer += chunk; });
  process.stdin.on('end', () => resolve(buffer));
  process.stdin.on('error', reject);
});

let byLicense;
try {
  byLicense = JSON.parse(raw);
} catch (e) {
  console.error('generate-notices: stdin is not the JSON pnpm licenses list produces');
  process.exit(1);
}

const packages = Object.entries(byLicense)
  .flatMap(([license, entries]) => entries.map(entry => ({ ...entry, license })))
  .sort((a, b) => a.name.localeCompare(b.name));

if (packages.length === 0) {
  // Fail loudly: an empty notices file is worse than none, because it looks authoritative.
  console.error('generate-notices: no package found; was `pnpm install` run first?');
  process.exit(1);
}

const licenses = [...new Set(packages.map(p => p.license))].sort();

const lines = [
  'THIRD-PARTY NOTICES',
  '',
  'This artefact bundles the front-end dependencies listed below. It is generated from the',
  'resolved dependency tree at build time; see account-console/oid4vp-account/scripts/.',
  '',
  `${packages.length} packages, under: ${licenses.join(', ')}.`,
  '',
  'The project\'s own licence and notice are in META-INF/LICENSE and META-INF/NOTICE.',
  '',
  '='.repeat(96),
  '',
];

for (const p of packages) {
  lines.push(`${p.name}@${(p.versions ?? []).join(', ')}`);
  lines.push(`  licence:  ${p.license}`);
  if (p.author) lines.push(`  author:   ${p.author}`);
  if (p.homepage) lines.push(`  homepage: ${p.homepage}`);
  lines.push('');
}

mkdirSync('generated', { recursive: true });
writeFileSync('generated/THIRD-PARTY-NOTICES.txt', lines.join('\n'), 'utf8');
console.log(`generate-notices: ${packages.length} packages, ${licenses.length} distinct licences`);
