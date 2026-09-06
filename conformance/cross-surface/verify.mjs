/**
 * Every surface must share one format. This opens each surface's output with
 * every other surface, so a change to one that breaks another fails loudly
 * instead of being discovered by a user.
 *
 * Covered: the WASM browser build, the Node SDK (which goes through the C
 * FFI), and the CLI. The Python SDK uses the same C FFI as Node, and is
 * covered by its own suite.
 *
 * Run after: cargo build -p hide-cli -p hide-ffi
 *            cargo build -p hide-wasm --target wasm32-unknown-unknown --release
 *            wasm-bindgen ... --target web --out-dir conformance/cross-surface/wasm
 */
import { execFileSync } from "node:child_process";
import { webcrypto } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

globalThis.crypto ??= webcrypto;

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..");

function binary(...names) {
  for (const name of names) {
    for (const profile of ["debug", "release"]) {
      const path = join(root, "target", profile, name);
      if (existsSync(path)) return path;
    }
  }
  return null;
}

const cliPath = binary("hide.exe", "hide");
const ffiPath = binary("hide_ffi.dll", "libhide_ffi.so", "libhide_ffi.dylib");
const wasmJs = join(here, "wasm", "hide_wasm.js");

// Missing pieces are a failure, never a silent skip: a skipped interop test is
// indistinguishable from a passing one.
const missing = [
  !cliPath && "the CLI (cargo build -p hide-cli)",
  !ffiPath && "the FFI library (cargo build -p hide-ffi)",
  !existsSync(wasmJs) && "the WASM build (see the header of this file)",
].filter(Boolean);
if (missing.length > 0) {
  console.error(`cannot run: missing ${missing.join(", ")}`);
  process.exit(1);
}

// Absolute paths must be file:// URLs for dynamic import on Windows.
const wasm = await import(pathToFileURL(wasmJs).href);
await wasm.default({
  module_or_path: await readFile(join(here, "wasm", "hide_wasm_bg.wasm")),
});

process.env.HIDE_LIBRARY = ffiPath;
const node = await import(
  pathToFileURL(join(root, "sdk", "node", "dist", "index.js")).href
);

const work = await mkdtemp(join(tmpdir(), "hide-cross-"));
const cli = (args, options = {}) =>
  execFileSync(cliPath, ["--experimental", "--quiet", ...args], {
    cwd: work,
    stdio: ["ignore", "pipe", "ignore"],
    ...options,
  });

const results = [];
const check = (name, condition) => results.push([name, Boolean(condition)]);

try {
  cli(["keygen", "--secret", "k.key", "--public", "k.pub", "--insecure-plaintext"]);
  const secretBytes = await readFile(join(work, "k.key"));
  const publicBytes = await readFile(join(work, "k.pub"));

  const wasmKey = wasm.SecretKey.load(secretBytes, undefined);
  const nodeKey = node.SecretKey.load(secretBytes);

  // WASM produced it.
  const fromWasm = wasm.encrypt(
    new TextEncoder().encode("from wasm"),
    publicBytes,
    "w.txt",
    null,
  );
  check("wasm -> node", node.decrypt(Buffer.from(fromWasm), nodeKey).data.toString() === "from wasm");
  await writeFile(join(work, "w.hide"), Buffer.from(fromWasm));
  cli(["open", "w.hide", "--secret", "k.key", "--output", "w.out"]);
  check("wasm -> cli", (await readFile(join(work, "w.out"))).toString() === "from wasm");

  // Node produced it.
  const fromNode = node.encrypt(Buffer.from("from node"), [publicBytes], { filename: "n.txt" });
  check(
    "node -> wasm",
    new TextDecoder().decode(wasm.decrypt(new Uint8Array(fromNode), wasmKey).data) === "from node",
  );
  await writeFile(join(work, "n.hide"), fromNode);
  cli(["open", "n.hide", "--secret", "k.key", "--output", "n.out"]);
  check("node -> cli", (await readFile(join(work, "n.out"))).toString() === "from node");

  // The CLI produced it.
  await writeFile(join(work, "c.txt"), "from cli");
  cli(["encrypt", "c.txt", "--recipient", "k.pub", "--output", "c.hide"]);
  const fromCli = await readFile(join(work, "c.hide"));
  check("cli -> node", node.decrypt(fromCli, nodeKey).data.toString() === "from cli");
  check(
    "cli -> wasm",
    new TextDecoder().decode(wasm.decrypt(new Uint8Array(fromCli), wasmKey).data) === "from cli",
  );

  // The frozen vectors must still open everywhere, or the format has moved.
  const vectors = join(root, "conformance", "vectors");
  const vectorKey = wasm.SecretKey.load(await readFile(join(vectors, "recipient.test-secret")), undefined);
  const vector = await readFile(join(vectors, "hello.hide"));
  const expected = await readFile(join(vectors, "hello.txt"));
  check("frozen vectors -> wasm", Buffer.from(wasm.decrypt(new Uint8Array(vector), vectorKey).data).equals(expected));
  check(
    "frozen vectors -> node",
    node.decrypt(vector, node.SecretKey.load(await readFile(join(vectors, "recipient.test-secret")))).data.equals(expected),
  );

  // A container from one surface must be rejected by all when damaged.
  const damaged = Uint8Array.from(fromCli);
  damaged[damaged.length - 1] ^= 1;
  let nodeRefused = false;
  try {
    node.decrypt(Buffer.from(damaged), nodeKey);
  } catch {
    nodeRefused = true;
  }
  let wasmRefused = false;
  try {
    wasm.decrypt(damaged, wasmKey);
  } catch {
    wasmRefused = true;
  }
  check("tampering refused by node", nodeRefused);
  check("tampering refused by wasm", wasmRefused);
} finally {
  await rm(work, { recursive: true, force: true });
}

for (const [name, ok] of results) {
  console.log(`${ok ? "PASS" : "FAIL"} ${name}`);
}
const failures = results.filter(([, ok]) => !ok);
if (failures.length > 0) {
  console.error(`${failures.length} surface(s) disagree about the format`);
  process.exit(1);
}
console.log(`all ${results.length} cross-surface checks passed`);
