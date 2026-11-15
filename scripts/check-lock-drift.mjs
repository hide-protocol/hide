#!/usr/bin/env node
// Three lockfiles describe what gets built: the root workspace (CLI, FFI, SDK
// core), the desktop crate (outside the workspace, its own Cargo.lock) and the
// fuzz crate (same). The wire format depends on the exact crypto crate
// versions, so when one lock moves a wire-relevant crate and another does not,
// the desktop app or the fuzzers run a different protocol than what ships.
// Dependabot once proposed exactly that (ml-dsa, hpke, sha2 bumped for /fuzz
// only). This fails CI on such a split. Node built-ins only; no dependencies.
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

// Crates whose version decides bytes on the wire or in a key file, plus the
// fuzzing harness itself. Anything else may legitimately differ.
const WIRE_RELEVANT = [
  "hpke",
  "ml-kem",
  "ml-dsa",
  "x-wing",
  "x25519-dalek",
  "ed25519-dalek",
  "curve25519-dalek",
  "chacha20poly1305",
  "sha2",
  "sha3",
  "hkdf",
  "hmac",
  "argon2",
  "minicbor",
  "zeroize",
  "ctutils",
  "mls-rs",
  "mls-rs-core",
  "mls-rs-codec",
  "mls-rs-crypto-rustcrypto",
  "libfuzzer-sys",
];

const LOCKS = [
  { label: "root", path: "Cargo.lock", required: true },
  { label: "desktop", path: "apps/hide-desktop/src-tauri/Cargo.lock", required: true },
  { label: "fuzz", path: "fuzz/Cargo.lock", required: false },
];

/** @returns {Map<string, Set<string>>} crate name -> every version in the lock */
function parseLock(path) {
  const versions = new Map();
  let name = null;
  for (const raw of readFileSync(path, "utf8").split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "[[package]]") {
      name = null;
      continue;
    }
    const nameMatch = /^name = "([^"]+)"$/.exec(line);
    if (nameMatch) {
      name = nameMatch[1];
      continue;
    }
    const versionMatch = /^version = "([^"]+)"$/.exec(line);
    if (versionMatch && name !== null) {
      if (!versions.has(name)) versions.set(name, new Set());
      versions.get(name).add(versionMatch[1]);
      name = null;
    }
  }
  return versions;
}

const loaded = [];
for (const lock of LOCKS) {
  const full = join(root, lock.path);
  if (!existsSync(full)) {
    if (lock.required) {
      console.error(`missing required lockfile: ${lock.path}`);
      process.exit(2);
    }
    console.log(`skip: ${lock.path} does not exist yet (nothing to compare for ${lock.label})`);
    continue;
  }
  loaded.push({ ...lock, versions: parseLock(full) });
}

const [rootLock, ...others] = loaded;
let drift = 0;
let compared = 0;

for (const other of others) {
  for (const crate of WIRE_RELEVANT) {
    const inRoot = rootLock.versions.get(crate);
    const inOther = other.versions.get(crate);
    // Only a single-version crate in BOTH locks is a clean comparison; a crate
    // that is legitimately duplicated (deny.toml attributes those) or absent
    // from one side is not drift.
    if (!inRoot || !inOther || inRoot.size !== 1 || inOther.size !== 1) continue;
    compared += 1;
    const [a] = inRoot;
    const [b] = inOther;
    if (a !== b) {
      drift += 1;
      console.error(`DRIFT ${crate}: root ${a} != ${other.label} ${b}  (${relative(root, join(root, other.path))})`);
    }
  }
}

const names = loaded.map((l) => l.label).join(", ");
if (drift > 0) {
  console.error(`${drift} wire-relevant crate(s) differ between the lockfiles (${names}); ${compared} compared`);
  console.error("fix: cargo update -p <crate> --precise <root version> --manifest-path <that Cargo.toml>");
  process.exit(1);
}
console.log(`lockfiles agree on every wire-relevant crate (${compared} compared across ${names})`);
