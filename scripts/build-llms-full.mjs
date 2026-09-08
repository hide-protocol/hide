// Regenerates llms-full.txt from the repository's own documents.
//
// Run from the repository root with plain Node, no install step:
//   node scripts/build-llms-full.mjs
// Add --check to exit 1 instead of writing when the committed file is stale
// (this is what .github/workflows/pages.yml does).
//
// The bundle exists so a crawler or an LLM can read every claim HIDE makes in
// one request. It is a concatenation only: the source files stay authoritative,
// which is why this script deliberately contains no prose of its own.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const output = join(root, "llms-full.txt");

const sources = [
  "README.md",
  "docs/faq.md",
  "docs/comparison.md",
  "docs/threat-model.md",
  "docs/audit-status.md",
  "docs/stability.md",
  "SECURITY.md",
];

const parts = sources.map((relative) => {
  // Normalise to LF so the result is byte-identical on Windows and Linux.
  const text = readFileSync(join(root, relative), "utf8").replace(/\r\n/g, "\n").trimEnd();
  return `# ===== ${relative} =====\n\n${text}\n`;
});
const bundle = parts.join("\n");

if (process.argv.includes("--check")) {
  const committed = existsSync(output) ? readFileSync(output, "utf8").replace(/\r\n/g, "\n") : "";
  if (committed !== bundle) {
    console.error("llms-full.txt is stale; run `node scripts/build-llms-full.mjs` and commit the result.");
    process.exit(1);
  }
  console.log("llms-full.txt is up to date.");
} else {
  writeFileSync(output, bundle);
  console.log(`wrote ${output} (${bundle.length} chars from ${sources.length} files)`);
}
