/**
 * Every surface must share one format. This opens each surface's output with
 * every other surface, so a change to one that breaks another fails loudly
 * instead of being discovered by a user.
 *
 * Covered: the WASM browser build, the Node SDK (which goes through the C
 * FFI), and the CLI — these three are always required. The Ruby, PHP and .NET
 * SDKs are driven through the small adapters in ./adapters, and are exercised
 * when their runtime is present. Set HIDE_CROSS_REQUIRE=ruby,php,dotnet to
 * turn an absent runtime into a failure (CI does this). The Python SDK uses
 * the same C FFI as Node, and is covered by its own suite.
 *
 * Run after: cargo build -p hide-cli -p hide-ffi
 *            cargo build -p hide-wasm --target wasm32-unknown-unknown --release
 *            wasm-bindgen ... --target web --out-dir conformance/cross-surface/wasm
 *            dotnet build conformance/cross-surface/adapters/dotnet   (for .NET)
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

// Adapters expose one interface: `<runtime> <adapter> <encrypt|decrypt> key in out`.
// A language is exercised when its runtime is on PATH; naming it in
// HIDE_CROSS_REQUIRE turns absence into a failure instead of a silent gap.
const adapters = join(here, "adapters");
const dotnetBinary = binaryIn(join(adapters, "dotnet", "bin"), "HideAdapter");
const languages = [
  {
    name: "ruby",
    command: "ruby",
    args: ["-I", join(root, "sdk", "ruby", "lib"), join(adapters, "ruby_adapter.rb")],
    probe: ["--version"],
  },
  {
    name: "php",
    command: "php",
    // Ubuntu ships ffi.enable=preload, which refuses FFI from a plain script.
    args: ["-d", "ffi.enable=1", join(adapters, "php_adapter.php")],
    probe: ["-d", "ffi.enable=1", "--version"],
  },
  {
    name: "dotnet",
    command: dotnetBinary ?? "HideAdapter",
    args: [],
    // The adapter itself is the probe: with no arguments it exits 2 on purpose.
    probe: null,
    available: Boolean(dotnetBinary),
  },
];

function binaryIn(dir, stem) {
  for (const name of [`${stem}.exe`, stem]) {
    for (const profile of ["Debug", "Release"]) {
      const path = join(dir, profile, "net8.0", name);
      if (existsSync(path)) return path;
    }
  }
  return null;
}

const required = (process.env.HIDE_CROSS_REQUIRE ?? "")
  .split(",")
  .map((name) => name.trim().toLowerCase())
  .filter(Boolean);

for (const language of languages) {
  if (language.available !== undefined) continue;
  try {
    execFileSync(language.command, language.probe, { stdio: "ignore" });
    language.available = true;
  } catch {
    language.available = false;
  }
}

const unknown = required.filter((name) => !languages.some((l) => l.name === name));
if (unknown.length > 0) {
  console.error(`HIDE_CROSS_REQUIRE names unknown surface(s): ${unknown.join(", ")}`);
  process.exit(1);
}
const absentButRequired = languages.filter((l) => required.includes(l.name) && !l.available);
if (absentButRequired.length > 0) {
  console.error(
    `HIDE_CROSS_REQUIRE demands ${absentButRequired.map((l) => l.name).join(", ")}, ` +
      "but the runtime (or, for dotnet, the built adapter) is absent",
  );
  process.exit(1);
}

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
  // These use the seed-based key file, because that is how every surface loads
  // an unprotected key; the v0.1 fixture beside them is the recipient key
  // itself and is covered by the Rust suite instead.
  const vectors = join(root, "conformance", "vectors");
  const vectorSeed = await readFile(join(vectors, "identity.test-seed"));
  const vectorKey = wasm.SecretKey.load(vectorSeed, undefined);
  const vector = await readFile(join(vectors, "identity.hide"));
  const expected = await readFile(join(vectors, "identity.txt"));
  check("frozen vectors -> wasm", Buffer.from(wasm.decrypt(new Uint8Array(vector), vectorKey).data).equals(expected));
  check(
    "frozen vectors -> node",
    node.decrypt(vector, node.SecretKey.load(vectorSeed)).data.equals(expected),
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

  // Signatures must cross surfaces too: a signature is worthless if only the
  // surface that produced it can check it.
  cli(["keygen", "--secret", "s.key", "--public", "s.pub", "--insecure-plaintext"]);
  const signingKey = await readFile(join(work, "s.key"));
  const context = new TextEncoder().encode("HIDE/0.5 cross-surface");
  const signed = new TextEncoder().encode("the signed message");

  const wasmSigner = wasm.SigningIdentity.load(signingKey, undefined);
  const nodeSigner = node.SigningIdentity.load(signingKey);
  const signingPublic = wasmSigner.publicKey();
  check(
    "both surfaces derive the same verifying key",
    Buffer.from(signingPublic).equals(Buffer.from(nodeSigner.publicKey())),
  );

  const wasmSignature = wasmSigner.sign(context, signed);
  const nodeSignature = nodeSigner.sign(context, signed);

  const verifies = (verifier, signature) => {
    try {
      verifier(signature);
      return true;
    } catch {
      return false;
    }
  };
  const byNode = (signature) =>
    node.verify(Buffer.from(signingPublic), Buffer.from(context), Buffer.from(signed), Buffer.from(signature));
  const byWasm = (signature) =>
    wasm.verify(signingPublic, context, signed, new Uint8Array(signature));

  check("wasm signature -> node", verifies(byNode, wasmSignature));
  check("node signature -> wasm", verifies(byWasm, nodeSignature));

  // A signature over a different message must fail everywhere, or the check
  // above proves only that the call returns.
  const otherMessage = new TextEncoder().encode("a different message");
  check(
    "node refuses a signature over another message",
    !verifies(
      (signature) =>
        node.verify(Buffer.from(signingPublic), Buffer.from(context), Buffer.from(otherMessage), Buffer.from(signature)),
      wasmSignature,
    ),
  );
  check(
    "wasm refuses a signature over another message",
    !verifies(
      (signature) => wasm.verify(signingPublic, context, otherMessage, new Uint8Array(signature)),
      nodeSignature,
    ),
  );

  // A challenge issued by one surface must be answerable by another, or
  // authentication could never span a client and a server written differently.
  const challenge = wasm.newChallenge("ssh://cross.example", 1000n, 60n);
  const nodeAnswer = nodeSigner.answer(Buffer.from(challenge));
  const spent = new wasm.SpentNonces();
  check(
    "wasm challenge answered by node",
    verifies(() => spent.accept(challenge, new Uint8Array(nodeAnswer), signingPublic, 1000n), null),
  );
  check(
    "the same answer is refused the second time",
    !verifies(() => spent.accept(challenge, new Uint8Array(nodeAnswer), signingPublic, 1000n), null),
  );

  // Each adapter language against the CLI, the frozen vectors, and damage.
  const run = (language, args) =>
    execFileSync(language.command, [...language.args, ...args], {
      cwd: work,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, HIDE_LIBRARY: ffiPath },
    });

  for (const language of languages.filter((l) => l.available)) {
    const tag = language.name;
    const message = `from ${tag}`;
    try {
      await writeFile(join(work, `${tag}.txt`), message);
      run(language, ["encrypt", "k.pub", `${tag}.txt`, `${tag}.hide`]);
      cli(["open", `${tag}.hide`, "--secret", "k.key", "--output", `${tag}.out`]);
      check(`${tag} -> cli`, (await readFile(join(work, `${tag}.out`))).toString() === message);

      run(language, ["decrypt", "k.key", "c.hide", `${tag}.cli.out`]);
      check(
        `cli -> ${tag}`,
        (await readFile(join(work, `${tag}.cli.out`))).toString() === "from cli",
      );

      run(language, [
        "decrypt",
        join(vectors, "identity.test-seed"),
        join(vectors, "identity.hide"),
        `${tag}.vector.out`,
      ]);
      check(
        `frozen vectors -> ${tag}`,
        (await readFile(join(work, `${tag}.vector.out`))).equals(expected),
      );

      await writeFile(join(work, `${tag}.damaged.hide`), Buffer.from(damaged));
      let refused = false;
      try {
        run(language, ["decrypt", "k.key", `${tag}.damaged.hide`, `${tag}.damaged.out`]);
      } catch {
        refused = true;
      }
      check(`tampering refused by ${tag}`, refused);
    } catch (error) {
      // A present runtime that cannot round-trip is a failure, not an absence.
      console.error(`${tag} adapter failed: ${error.stderr?.toString() || error.message}`);
      check(`${tag} adapter runs`, false);
    }
  }
} finally {
  await rm(work, { recursive: true, force: true });
}

for (const [name, ok] of results) {
  console.log(`${ok ? "PASS" : "FAIL"} ${name}`);
}

// Print the truth about coverage: a reader of CI output must be able to see
// which surfaces actually ran, not infer it from the absence of failures.
const exercised = ["wasm", "node", "cli", ...languages.filter((l) => l.available).map((l) => l.name)];
const absent = languages.filter((l) => !l.available).map((l) => l.name);
console.log(`exercised: ${exercised.join(", ")}`);
console.log(absent.length > 0 ? `absent: ${absent.join(", ")}` : "absent: none");

const failures = results.filter(([, ok]) => !ok);
if (failures.length > 0) {
  console.error(`${failures.length} surface(s) disagree about the format`);
  process.exit(1);
}
console.log(`all ${results.length} cross-surface checks passed`);
