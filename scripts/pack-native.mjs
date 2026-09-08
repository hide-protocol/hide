// Turns one compiled hide-ffi library into the per-platform package each
// ecosystem expects. Run once per target, on the machine that built it.
//
//   node scripts/pack-native.mjs npm <target> <version> <library-path> <out-dir>
//   node scripts/pack-native.mjs gem <target> <version> <library-path>

import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const table = JSON.parse(readFileSync(join(root, "sdk", "native-targets.json"), "utf8"));

const [kind, target, version, libraryPath, outDir] = process.argv.slice(2);
const entry = table.targets.find((t) => t.target === target);
if (!entry) {
  console.error(`unknown target ${target}; add it to sdk/native-targets.json`);
  process.exit(1);
}

if (kind === "npm") {
  const dir = join(outDir, entry.npm);
  mkdirSync(dir, { recursive: true });
  copyFileSync(libraryPath, join(dir, entry.library));
  copyFileSync(join(root, "LICENSE"), join(dir, "LICENSE"));

  const manifest = {
    name: `@hide-protocol/${entry.npm}`,
    version,
    description:
      `The compiled HIDE core for ${entry.target}, installed automatically by hide-protocol. ` +
      "Experimental, unaudited.",
    license: "Apache-2.0",
    keywords: ["post-quantum", "encryption", "native", "prebuilt"],
    // npm refuses to install a platform package on the wrong machine, which is
    // what makes the optional dependencies resolve to exactly one of these.
    os: [entry.nodePlatform],
    cpu: [entry.nodeArch],
    ...(entry.libc ? { libc: [entry.libc] } : {}),
    files: [entry.library, "LICENSE"],
    repository: { type: "git", url: "git+https://github.com/hide-protocol/hide.git" },
    bugs: { url: "https://github.com/hide-protocol/hide/issues" },
    homepage: "https://github.com/hide-protocol/hide",
  };
  writeFileSync(join(dir, "package.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(
    join(dir, "README.md"),
    `# @hide-protocol/${entry.npm}\n\nThe compiled HIDE core for \`${entry.target}\`. ` +
      "You do not install this directly: `hide-protocol` pulls in the one package " +
      "matching your machine.\n",
  );
  console.log(dir);
} else if (kind === "gem") {
  // The Ruby loader looks beside binding.rb, and the gemspec already globs it.
  const dir = join(root, "sdk", "ruby", "lib", "hide_protocol");
  copyFileSync(libraryPath, join(dir, entry.library));
  console.log(entry.gem);
} else {
  console.error(`unknown kind ${kind}; expected npm or gem`);
  process.exit(1);
}
