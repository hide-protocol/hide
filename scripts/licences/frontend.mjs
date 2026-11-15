// Prints the licence notices of the JavaScript packages that Vite bundles into
// the desktop application's user interface, for appending to
// THIRD-PARTY-LICENSES.txt. cargo-about sees only Rust crates, and the bundled
// JavaScript (React and the Tauri API, all MIT or MIT/Apache-2.0) carries
// notice requirements of its own; the minified bundle keeps no licence
// comments.
//
//   usage: node scripts/licences/frontend.mjs <app-directory>
//
// The set is the production dependency closure read from the installed
// node_modules, so it follows the lockfile without naming packages here. It
// reads files only: no package manager is invoked.

import { existsSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

const appDir = resolve(process.argv[2] ?? "");
if (!process.argv[2] || !existsSync(join(appDir, "package.json"))) {
  console.error("usage: node scripts/licences/frontend.mjs <app-directory>");
  process.exit(2);
}

// Node's own resolution rule: the nearest node_modules/<name> walking upward
// from the directory of the package that asks. pnpm's layout relies on it.
function locate(name, fromDir) {
  for (let dir = fromDir; ; dir = dirname(dir)) {
    const candidate = join(dir, "node_modules", name);
    if (existsSync(join(candidate, "package.json"))) {
      return realpathSync(candidate);
    }
    if (dirname(dir) === dir) {
      return null;
    }
  }
}

const found = new Map();
const queue = [{ deps: readManifest(appDir).dependencies ?? {}, from: appDir }];

function readManifest(dir) {
  return JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
}

while (queue.length > 0) {
  const { deps, from } = queue.shift();
  for (const name of Object.keys(deps)) {
    const dir = locate(name, from);
    if (!dir) {
      // A production dependency that is not installed means the notices would
      // silently miss a package that is in the bundle.
      console.error(`cannot find ${name} from ${from}; run the install first`);
      process.exit(1);
    }
    const manifest = readManifest(dir);
    const key = `${manifest.name}@${manifest.version}`;
    if (found.has(key)) {
      continue;
    }
    found.set(key, { dir, manifest });
    // Optional and peer dependencies are not followed: what is bundled is what
    // is imported, and an optional package that is absent is not an error.
    queue.push({ deps: manifest.dependencies ?? {}, from: dir });
  }
}

if (found.size === 0) {
  console.error(`${appDir} has no production dependencies; nothing to list`);
  process.exit(1);
}

const isNotice = /^(licen[sc]e|copying|notice)/i;
const rule = "=".repeat(80);
const out = [];

// Some packages ship only a machine-readable SPDX summary that names their
// licences without reproducing them. The summary alone does not satisfy the
// notice clause, so such a package is accepted only when the full text of one
// of the licences it is offered under is printed for another package in this
// same file; otherwise the run fails rather than ship an incomplete notice.
const fullTextMarkers = {
  MIT: "Permission is hereby granted, free of charge",
  "Apache-2.0": "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION",
};
const printedTexts = [];
const summaryOnly = [];

out.push("");
out.push(rule);
out.push("JavaScript packages bundled into the user interface");
out.push(rule);

for (const key of [...found.keys()].sort()) {
  const { dir, manifest } = found.get(key);
  const files = readdirSync(dir).filter((file) => isNotice.test(file)).sort();
  if (files.length === 0) {
    console.error(`${key} ships no licence file in ${dir}`);
    process.exit(1);
  }
  const licence =
    typeof manifest.license === "string" ? manifest.license : "see the text below";
  out.push("");
  out.push(`${manifest.name} ${manifest.version}  (${licence})`);
  out.push(`  https://www.npmjs.com/package/${manifest.name}/v/${manifest.version}`);
  let hasFullText = false;
  for (const file of files) {
    const text = readFileSync(join(dir, file), "utf8").replace(/\r\n?/g, "\n").trimEnd();
    out.push("");
    out.push(`--- ${manifest.name}: ${file}`);
    out.push(text);
    if (Object.values(fullTextMarkers).some((marker) => text.includes(marker))) {
      hasFullText = true;
      printedTexts.push(text);
    }
  }
  if (!hasFullText) {
    summaryOnly.push({ key, licence, at: out.length });
    out.push("");
    out.push(`--- ${manifest.name}: licence text`);
    out.push(""); // filled in below, once every package has been read
  }
}

for (const { key, licence, at } of summaryOnly) {
  const offered = licence.split(/\s+(?:OR|AND)\s+|[()]/).map((id) => id.trim()).filter(Boolean);
  const covered = offered.filter(
    (id) => fullTextMarkers[id] && printedTexts.some((text) => text.includes(fullTextMarkers[id])),
  );
  if (covered.length === 0) {
    console.error(
      `${key} ships no licence text, and the text of none of its licences (${licence}) ` +
        "is printed for another package",
    );
    process.exit(1);
  }
  out[at + 2] =
    `This package ships only the summary above, not the licence texts. It is offered\n` +
    `under ${licence}; the full text of ${covered.join(" and of ")} is printed elsewhere in this\n` +
    "section and applies to this package with the copyright notice given above.";
}

process.stdout.write(`${out.join("\n")}\n`);
