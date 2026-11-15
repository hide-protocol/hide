import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { basename, delimiter, dirname, isAbsolute, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import { BINDING_VERSION, checkVersion, libraryPath } from "./binding.js";
import {
  AuthenticationError,
  ChallengeAudienceError,
  ChallengeExpiredError,
  ChallengeReplayedError,
  MalformedError,
  NoMatchingRecipientError,
  NotAKeyError,
  PUBLIC_KEY_LEN,
  SIGNATURE_LEN,
  SecretKey,
  SigningIdentity,
  SpentNonces,
  VERIFYING_KEY_LEN,
  WrongPassphraseError,
  armorPublicKey,
  dearmorPublicKey,
  decrypt,
  encrypt,
  epochPublicKey,
  identityHead,
  identityTrustsDevice,
  inspectKey,
  newChallenge,
  verify,
  verifyCheckpoint,
  verifyConsistency,
  verifyEpochChain,
  verifyEpochChainBound,
  verifyIdentity,
  verifyIdentityPinned,
  verifyInclusion,
  version,
} from "./index.js";
import {
  bindingEpoch,
  bindingEpochStranger,
  bindingHijackedLog,
  bindingIdentityLog,
  bindingRecovery,
  bindingRecoveryForged,
  bindingRoot,
  checkpoint3,
  checkpointLogKey,
  checkpointTampered,
  checkpointWitnessKey,
  consistencyPath,
  epochBroken,
  epochChain,
  epochPublicKey1,
  identityDeviceLaptop,
  identityDevicePhone,
  identityHead as identityHeadFixture,
  identityLog,
  identityLogLegacy,
  identityRecovery,
  identityTampered,
  identityTamperedLegacy,
  inclusionPath,
  leaf,
  otherLeaf,
  rewrittenRoot,
  rootAt5,
  treeRoot,
} from "./fixtures.js";

test("round trip carries metadata", () => {
  const secret = SecretKey.generate();
  try {
    const publicKey = secret.publicKey();
    assert.equal(publicKey.length, PUBLIC_KEY_LEN);

    const message = Buffer.from("nume,suma\nAna,9000\n");
    const box = encrypt(message, [publicKey], {
      filename: "salarii.csv",
      mediaType: "text/csv",
    });
    assert.ok(!box.includes(Buffer.from("Ana")), "plaintext leaked");

    const opened = decrypt(box, secret);
    assert.deepEqual(opened.data, message);
    assert.equal(opened.filename, "salarii.csv");
    assert.equal(opened.mediaType, "text/csv");
  } finally {
    secret.close();
  }
});

test("single-byte mutations are rejected", () => {
  const secret = SecretKey.generate();
  try {
    const box = encrypt(Buffer.from("confidential"), [secret.publicKey()]);
    for (const offset of [0, 8, 15, 40, box.length >> 1, box.length - 1]) {
      const damaged = Buffer.from(box);
      damaged.writeUInt8(damaged.readUInt8(offset) ^ 0x40, offset);
      assert.throws(() => decrypt(damaged, secret));
    }
  } finally {
    secret.close();
  }
});

test("truncation and extension fail", () => {
  const secret = SecretKey.generate();
  try {
    const box = encrypt(Buffer.from("payload"), [secret.publicKey()]);
    assert.throws(() => decrypt(box.subarray(0, box.length - 1), secret));
    assert.throws(() => decrypt(Buffer.concat([box, Buffer.of(0)]), secret));
  } finally {
    secret.close();
  }
});

test("the wrong key cannot decrypt", () => {
  const alice = SecretKey.generate();
  const bob = SecretKey.generate();
  try {
    const box = encrypt(Buffer.from("for alice"), [alice.publicKey()]);
    assert.throws(() => decrypt(box, bob), NoMatchingRecipientError);
  } finally {
    alice.close();
    bob.close();
  }
});

test("many recipients share one payload", () => {
  const keys = [SecretKey.generate(), SecretKey.generate(), SecretKey.generate()];
  try {
    const box = encrypt(
      Buffer.from("shared"),
      keys.map((key) => key.publicKey()),
    );
    for (const key of keys) {
      assert.equal(decrypt(box, key).data.toString(), "shared");
    }
  } finally {
    keys.forEach((key) => key.close());
  }
});

test("protected keys round trip and reject a wrong passphrase", () => {
  const secret = SecretKey.generate();
  const publicKey = secret.publicKey();
  const sealed = secret.protect("correct horse battery");
  secret.close();

  assert.equal(inspectKey(sealed), "protected");
  assert.throws(() => SecretKey.load(sealed, "wrong"), WrongPassphraseError);
  assert.throws(() => SecretKey.load(sealed), WrongPassphraseError);

  const reopened = SecretKey.load(sealed, "correct horse battery");
  try {
    assert.deepEqual(reopened.publicKey(), publicKey);
  } finally {
    reopened.close();
  }
});

test("a short passphrase is refused", () => {
  const secret = SecretKey.generate();
  try {
    assert.throws(() => secret.protect("short"), RangeError);
  } finally {
    secret.close();
  }
});

test("armor round trips", () => {
  const secret = SecretKey.generate();
  try {
    const publicKey = secret.publicKey();
    const text = armorPublicKey(publicKey);
    assert.ok(text.startsWith("hide-public-key:"));
    assert.deepEqual(dearmorPublicKey(text), publicKey);
    assert.throws(() => dearmorPublicKey("not a key"));
  } finally {
    secret.close();
  }
});

test("recipient count and key length are bounded", () => {
  const secret = SecretKey.generate();
  try {
    const publicKey = secret.publicKey();
    assert.throws(() => encrypt(Buffer.from("x"), []), RangeError);
    assert.throws(
      () => encrypt(Buffer.from("x"), Array(65).fill(publicKey)),
      RangeError,
    );
    assert.throws(() => encrypt(Buffer.from("x"), [Buffer.from("short")]), RangeError);
  } finally {
    secret.close();
  }
});

test("a closed key cannot be used and never prints key material", () => {
  const secret = SecretKey.generate();
  const publicKey = secret.publicKey();
  assert.equal(JSON.stringify(secret), '"[hide.SecretKey]"');
  assert.ok(!JSON.stringify(secret).includes(publicKey.toString("hex").slice(0, 16)));

  secret.close();
  secret.close(); // idempotent
  assert.throws(() => secret.publicKey(), TypeError);
});

test("empty payloads are valid", () => {
  const secret = SecretKey.generate();
  try {
    const box = encrypt(Buffer.alloc(0), [secret.publicKey()]);
    assert.equal(decrypt(box, secret).data.length, 0);
  } finally {
    secret.close();
  }
});

test("a corrupt container yields an authentication error, not a crash", () => {
  const secret = SecretKey.generate();
  try {
    assert.throws(
      () => decrypt(Buffer.from("this is not a HIDE container at all"), secret),
      AuthenticationError,
    );
  } finally {
    secret.close();
  }
});

const PASSPHRASE = "correct horse battery staple";
const CONTEXT = Buffer.from("example/node test");
const MESSAGE = Buffer.from("the message");

function identity(): SigningIdentity {
  return SigningIdentity.load(SigningIdentity.generate(PASSPHRASE), PASSPHRASE);
}

test("signs and verifies", () => {
  const signer = identity();
  try {
    const publicKey = signer.publicKey();
    assert.equal(publicKey.length, VERIFYING_KEY_LEN);
    const signature = signer.sign(CONTEXT, MESSAGE);
    assert.equal(signature.length, SIGNATURE_LEN);
    verify(publicKey, CONTEXT, MESSAGE, signature);
  } finally {
    signer.close();
  }
});

test("a changed message does not verify", () => {
  const signer = identity();
  try {
    const signature = signer.sign(CONTEXT, MESSAGE);
    assert.throws(
      () => verify(signer.publicKey(), CONTEXT, Buffer.from("the messagE"), signature),
      AuthenticationError,
    );
  } finally {
    signer.close();
  }
});

test("a different context does not verify", () => {
  const signer = identity();
  try {
    const signature = signer.sign(CONTEXT, MESSAGE);
    assert.throws(
      () =>
        verify(signer.publicKey(), Buffer.from("another context"), MESSAGE, signature),
      AuthenticationError,
    );
  } finally {
    signer.close();
  }
});

// Spec §15.2: the generic API must not mint protocol signatures.
test("reserved protocol contexts are refused", () => {
  const signer = identity();
  try {
    for (const context of ["HIDE/0.6 identity entry", "HIDE/1.0 container", "HIDE/"]) {
      assert.throws(() => signer.sign(Buffer.from(context), MESSAGE), RangeError);
    }
  } finally {
    signer.close();
  }
});

test("another identity cannot be impersonated", () => {
  const signer = identity();
  const impostor = identity();
  try {
    const signature = impostor.sign(CONTEXT, MESSAGE);
    assert.throws(
      () => verify(signer.publicKey(), CONTEXT, MESSAGE, signature),
      AuthenticationError,
    );
  } finally {
    signer.close();
    impostor.close();
  }
});

test("an encryption-only key cannot sign", () => {
  const secret = SecretKey.generate();
  const sealed = secret.protect(PASSPHRASE);
  secret.close();
  assert.throws(() => SigningIdentity.load(sealed, PASSPHRASE), NotAKeyError);
});

test("a challenge is answered once and then refused", () => {
  const prover = identity();
  const spent = new SpentNonces("ssh://host.example");
  try {
    const publicKey = prover.publicKey();
    const challenge = newChallenge("ssh://host.example", 1000, 60);
    const answer = prover.answer(challenge);

    spent.accept(challenge, answer, publicKey, 1000);
    // The identical valid answer, presented again.
    assert.throws(
      () => spent.accept(challenge, answer, publicKey, 1000),
      ChallengeReplayedError,
    );
  } finally {
    spent.close();
    prover.close();
  }
});

test("an answer after the window is refused", () => {
  const prover = identity();
  const spent = new SpentNonces("ssh://host.example");
  try {
    const challenge = newChallenge("ssh://host.example", 1000, 60);
    const answer = prover.answer(challenge);
    assert.throws(
      () => spent.accept(challenge, answer, prover.publicKey(), 1100),
      ChallengeExpiredError,
    );
  } finally {
    spent.close();
    prover.close();
  }
});

test("an answer for another audience is refused", () => {
  // A challenge relayed from another service is a genuine challenge with a
  // genuine answer; only the audience says it was not minted for us.
  const prover = identity();
  try {
    const publicKey = prover.publicKey();
    const challenge = newChallenge("some.other.service", 1000, 60);
    const answer = prover.answer(challenge);

    const spent = new SpentNonces("ssh://host.example");
    try {
      assert.throws(
        () => spent.accept(challenge, answer, publicKey, 1000),
        ChallengeAudienceError,
      );
      // Refused, and not spent: our own answer for this audience still works.
      const ours = newChallenge("ssh://host.example", 1000, 60);
      spent.accept(ours, prover.answer(ours), publicKey, 1000);
    } finally {
      spent.close();
    }

    // A record that names no audience accepts nothing.
    const unnamed = new SpentNonces("");
    try {
      assert.throws(
        () => unnamed.accept(challenge, answer, publicKey, 1000),
        ChallengeAudienceError,
      );
    } finally {
      unnamed.close();
    }
  } finally {
    prover.close();
  }
});

test("a closed identity cannot sign and never prints key material", () => {
  const signer = identity();
  assert.equal(JSON.stringify(signer), '"[hide.SigningIdentity]"');
  signer.close();
  signer.close(); // idempotent
  assert.throws(() => signer.sign(CONTEXT, MESSAGE), TypeError);
});

test("an identity log reports the devices it trusts", () => {
  // Four events: create, enrol phone, enrol laptop, revoke laptop.
  assert.equal(verifyIdentity(identityLog, identityRecovery), 2);
});

test("a revoked device is no longer trusted", () => {
  assert.equal(
    identityTrustsDevice(identityLog, identityRecovery, identityDevicePhone),
    true,
  );
  assert.equal(
    identityTrustsDevice(identityLog, identityRecovery, identityDeviceLaptop),
    false,
  );
});

test("a tampered log is refused", () => {
  assert.throws(
    () => verifyIdentity(identityTampered, identityRecovery),
    AuthenticationError,
  );
  // Bytes that do not decode at all are a different failure from bytes that
  // decode and do not verify.
  assert.throws(
    () => verifyIdentity(Buffer.from("not a log"), identityRecovery),
    MalformedError,
  );
});

test("the head names this exact history", () => {
  const head = identityHead(identityLog, identityRecovery);
  assert.deepEqual(head, identityHeadFixture);
  assert.equal(head.length, 32);
});

test("each log entry is framed as an array of seven", () => {
  // array(4), array(7), sequence 0, tag 1: what a generic CBOR reader expects.
  assert.deepEqual([...identityLog.subarray(0, 4)], [0x84, 0x87, 0x00, 0x01]);
});

test("a log written by 0.6-0.8 still opens and names the same history", () => {
  assert.deepEqual([...identityLogLegacy.subarray(0, 2)], [0x84, 0x86]);
  assert.equal(verifyIdentity(identityLogLegacy, identityRecovery), 2);
  assert.equal(
    identityTrustsDevice(identityLogLegacy, identityRecovery, identityDeviceLaptop),
    false,
  );
  assert.deepEqual(
    identityHead(identityLogLegacy, identityRecovery),
    identityHeadFixture,
  );
  assert.throws(
    () => verifyIdentity(identityTamperedLegacy, identityRecovery),
    AuthenticationError,
  );
});

test("an epoch chain verifies and yields keys", () => {
  assert.equal(verifyEpochChain(epochChain), 3);
  assert.deepEqual(epochPublicKey(epochChain, 1), epochPublicKey1);
});

test("an epoch beyond the chain is refused", () => {
  assert.throws(() => epochPublicKey(epochChain, 3), RangeError);
});

test("a spliced epoch chain does not verify", () => {
  assert.throws(() => verifyEpochChain(epochBroken), AuthenticationError);
});

test("an inclusion proof verifies only for its own leaf", () => {
  verifyInclusion(leaf, 3, 8, inclusionPath, treeRoot);
  assert.throws(
    () => verifyInclusion(otherLeaf, 3, 8, inclusionPath, treeRoot),
    AuthenticationError,
  );
});

test("a path that is not whole hashes is refused", () => {
  assert.throws(
    () => verifyInclusion(leaf, 3, 8, inclusionPath.subarray(0, -1), treeRoot),
    RangeError,
  );
});

test("a consistency proof catches a rewritten history", () => {
  verifyConsistency(5, 8, consistencyPath, rootAt5, treeRoot);
  // Same size, one entry silently replaced.
  assert.throws(
    () => verifyConsistency(5, 8, consistencyPath, rootAt5, rewrittenRoot),
    AuthenticationError,
  );
});

// Exactly AuthenticationError: a MalformedError here would mean the check never
// got as far as verifying, and the test would pass for the wrong reason.
function assertForgery(call: () => unknown): void {
  assert.throws(call, (error: unknown) => {
    assert.ok(error instanceof AuthenticationError);
    assert.ok(!(error instanceof MalformedError));
    return true;
  });
}

test("a pinned identity verifies against its root", () => {
  assert.equal(
    verifyIdentityPinned(bindingIdentityLog, bindingRecovery, bindingRoot),
    2,
  );
});

test("a hijacked log is refused even with a forged recovery binding", () => {
  assertForgery(() =>
    verifyIdentityPinned(bindingHijackedLog, bindingRecovery, bindingRoot),
  );
  assertForgery(() =>
    verifyIdentityPinned(bindingHijackedLog, bindingRecoveryForged, bindingRoot),
  );
});

test("a log under another root is refused", () => {
  assertForgery(() =>
    verifyIdentityPinned(bindingIdentityLog, bindingRecovery, Buffer.alloc(32)),
  );
});

test("a truncated recovery binding is malformed", () => {
  assert.throws(
    () =>
      verifyIdentityPinned(
        bindingIdentityLog,
        bindingRecovery.subarray(0, 100),
        bindingRoot,
      ),
    MalformedError,
  );
});

test("an epoch chain bound to the identity verifies", () => {
  assert.equal(
    verifyEpochChainBound(
      bindingIdentityLog,
      bindingRecovery,
      bindingRoot,
      epochChain,
      bindingEpoch,
    ),
    3,
  );
});

test("an epoch chain bound by a stranger is refused", () => {
  assertForgery(() =>
    verifyEpochChainBound(
      bindingIdentityLog,
      bindingRecovery,
      bindingRoot,
      epochChain,
      bindingEpochStranger,
    ),
  );
});

test("a checkpoint verifies and yields size and root", () => {
  const { size, root } = verifyCheckpoint(
    checkpoint3,
    "log.example/hide",
    checkpointLogKey,
  );
  assert.equal(size, 3n);
  assert.equal(root.length, 32);
});

test("a checkpoint is refused when altered, misattributed or mis-keyed", () => {
  assertForgery(() =>
    verifyCheckpoint(checkpointTampered, "log.example/hide", checkpointLogKey),
  );
  assertForgery(() =>
    verifyCheckpoint(checkpoint3, "other.example", checkpointLogKey),
  );
  assertForgery(() =>
    verifyCheckpoint(checkpoint3, "log.example/hide", checkpointWitnessKey),
  );
});

// --- text that becomes a C string -------------------------------------------

// A passphrase that is long enough on its own, then a NUL and more: a C string
// read stops at the NUL, so the core would see only the first part.
const SPLIT = "longenough\0rest";
const NUL = /NUL/;

test("a passphrase with an embedded NUL is refused, not truncated", () => {
  const secret = SecretKey.generate();
  try {
    assert.throws(() => secret.protect(SPLIT), RangeError);
    assert.throws(() => secret.protect(SPLIT), NUL);
    const sealed = secret.protect("longenough");
    // Opening must refuse too: accepting it here would mean the text before
    // the NUL is what unlocks the key.
    assert.throws(() => SecretKey.load(sealed, SPLIT), RangeError);
  } finally {
    secret.close();
  }

  assert.throws(() => SigningIdentity.generate(SPLIT), RangeError);
  const sealedIdentity = SigningIdentity.generate("longenough");
  assert.throws(() => SigningIdentity.load(sealedIdentity, SPLIT), RangeError);
  // The same file still opens under the passphrase it was sealed with.
  SigningIdentity.load(sealedIdentity, "longenough").close();
});

test("every other text argument refuses an embedded NUL", () => {
  const secret = SecretKey.generate();
  try {
    const publicKey = secret.publicKey();
    const payload = Buffer.from("x");
    assert.throws(
      () => encrypt(payload, [publicKey], { filename: "report.txt\0.exe" }),
      /filename must not contain a NUL/,
    );
    assert.throws(
      () => encrypt(payload, [publicKey], { mediaType: "text/plain\0x" }),
      /mediaType must not contain a NUL/,
    );
    assert.throws(
      () => dearmorPublicKey(`${armorPublicKey(publicKey)}\0trailing`),
      RangeError,
    );
  } finally {
    secret.close();
  }
  assert.throws(() => newChallenge("app.example\0.evil.example", 1000, 60), RangeError);
  assert.throws(() => new SpentNonces("app.example\0.evil.example"), RangeError);
  assert.throws(
    () => verifyCheckpoint(checkpoint3, "log.example\0/hide", checkpointLogKey),
    RangeError,
  );
});

test("a filename that is not one portable file name is refused", () => {
  const secret = SecretKey.generate();
  try {
    const publicKey = secret.publicKey();
    const payload = Buffer.from("x");
    for (const filename of [
      "a/b",
      "a\\b",
      "..",
      "CON",
      "com1.txt",
      "trailing.",
      "trailing ",
      "tab\there",
      "what?.txt",
      "x".repeat(256),
    ]) {
      assert.throws(() => encrypt(payload, [publicKey], { filename }), filename);
    }
    for (const filename of ["report.txt", "CONSOLE.txt", "x".repeat(255)]) {
      assert.equal(decrypt(encrypt(payload, [publicKey], { filename }), secret).filename, filename);
    }
  } finally {
    secret.close();
  }
});

test("text arguments must be strings", () => {
  const secret = SecretKey.generate();
  try {
    const notText = Buffer.from("a buffer passphrase") as unknown as string;
    assert.throws(() => secret.protect(notText), TypeError);
    assert.throws(() => newChallenge(notText, 1000, 60), TypeError);
    assert.throws(() => new SpentNonces(notText), TypeError);
  } finally {
    secret.close();
  }
});

// --- one owner per native pointer --------------------------------------------

type Constructor = new (...args: unknown[]) => unknown;

test("a handle cannot be built around an existing native pointer", () => {
  // TypeScript's `private constructor` is erased at run time. Before the
  // guard, plain JavaScript could wrap one pointer twice and free it twice.
  const secret = SecretKey.generate();
  const signer = identity();
  try {
    assert.throws(() => new (SecretKey as unknown as Constructor)(secret.handle), TypeError);
    assert.throws(
      () => new (SecretKey as unknown as Constructor)(Symbol("hide.internal"), secret.handle),
      TypeError,
    );
    assert.throws(() => new (SigningIdentity as unknown as Constructor)(secret.handle), TypeError);
    assert.throws(() => Reflect.construct(SecretKey, []), /SecretKey\.generate\(\)/);
    // The original is untouched by the refused attempts.
    assert.equal(secret.publicKey().length, PUBLIC_KEY_LEN);
    assert.equal(signer.publicKey().length, VERIFYING_KEY_LEN);
  } finally {
    secret.close();
    signer.close();
  }
});

test("a handle does not survive cloning, so it cannot reach another thread", () => {
  // Every call into the core is synchronous on the calling thread, which is
  // why SpentNonces needs no lock here. The structured clone algorithm is what
  // postMessage uses to send a value to a worker: it carries no native pointer.
  const secret = SecretKey.generate();
  const spent = new SpentNonces("ssh://host.example");
  try {
    for (const handle of [secret, spent]) {
      const clone = structuredClone(handle) as unknown as Record<string, unknown>;
      assert.ok(!(clone instanceof SecretKey) && !(clone instanceof SpentNonces));
      assert.deepEqual(Reflect.ownKeys(clone), []);
      assert.equal(typeof clone.close, "undefined");
    }
    assert.deepEqual({ ...secret }, {});
  } finally {
    spent.close();
    secret.close();
  }
});

// --- how the native library is found -----------------------------------------

const bindingUrl = new URL("./binding.js", import.meta.url).href;
const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const libraryFile = basename(libraryPath);
const NO_OVERRIDE = { HIDE_LIBRARY: undefined, HIDE_ALLOW_LIBRARY_OVERRIDE: undefined };

function probeSource(binding: string): string {
  return `
    try {
      const binding = await import(${JSON.stringify(binding)});
      console.log("LOADED " + binding.libraryPath);
    } catch (error) {
      console.log("ERROR " + error.message);
    }
  `;
}

/**
 * Imports the binding in a fresh process and returns what it printed. The
 * library is chosen once, at import, so only a new process can show how a
 * different environment is treated.
 */
function probe(
  changes: Record<string, string | undefined>,
  cwd?: string,
  binding: string = bindingUrl,
): string {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const [name, value] of Object.entries(changes)) {
    // Windows variable names are case-insensitive, and `Path` beside `PATH`
    // would leave it to chance which one the child sees.
    for (const existing of Object.keys(env)) {
      if (existing.toUpperCase() === name.toUpperCase()) delete env[existing];
    }
    if (value !== undefined) env[name] = value;
  }
  const done = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", probeSource(binding)],
    { env, cwd, encoding: "utf8", timeout: 120_000 },
  );
  assert.equal(done.status, 0, done.stderr);
  return done.stdout.trim();
}

// Put in front of what is already there: the interpreter itself may need the
// existing value to start.
function inFront(directory: string, name: string): string {
  const existing = Object.entries(process.env).find(
    ([key]) => key.toUpperCase() === name.toUpperCase(),
  )?.[1];
  return existing ? [directory, existing].join(delimiter) : directory;
}

// The two names a platform package can have here; which one applies depends on
// the C library, and the tests should not repeat that detection.
const platformPackages = ["", "-musl"].map(
  (suffix) => `${process.platform}-${process.arch}${suffix}`,
);

function plantPlatformPackages(modules: string): string[] {
  return platformPackages.map((name) => {
    const directory = join(modules, "@hide-protocol", name);
    mkdirSync(directory, { recursive: true });
    copyFileSync(libraryPath, join(directory, libraryFile));
    writeFileSync(
      join(directory, "package.json"),
      JSON.stringify({ name: `@hide-protocol/${name}`, version: BINDING_VERSION }),
    );
    return join(directory, libraryFile);
  });
}

function koffiRoot(): string {
  let directory = dirname(createRequire(import.meta.url).resolve("koffi"));
  while (!existsSync(join(directory, "package.json"))) directory = dirname(directory);
  return directory;
}

/**
 * Lays this package out the way a package manager installs it, with its
 * platform package beside it, and returns the URL of the installed binding.
 */
function install(
  root: string,
  layout: "npm" | "pnpm",
  version: string = BINDING_VERSION,
): { binding: string; libraries: string[] } {
  const modules =
    layout === "npm"
      ? join(root, "node_modules")
      : join(root, "node_modules", ".pnpm", `hide-protocol@${version}`, "node_modules");
  const installed = join(modules, "hide-protocol");
  mkdirSync(join(installed, "dist"), { recursive: true });
  copyFileSync(join(packageRoot, "dist", "binding.js"), join(installed, "dist", "binding.js"));
  const manifest = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8")) as {
    version: string;
  };
  manifest.version = version;
  writeFileSync(join(installed, "package.json"), JSON.stringify(manifest));
  symlinkSync(koffiRoot(), join(modules, "koffi"), "junction");
  return {
    binding: pathToFileURL(join(installed, "dist", "binding.js")).href,
    libraries: plantPlatformPackages(modules),
  };
}

function temporaryDirectory(prefix: string): string {
  // Resolved, because a child reports paths with symbolic links followed.
  return realpathSync(mkdtempSync(join(tmpdir(), prefix)));
}

// With no override, either a copy shipped with the package loaded, or nothing
// did and the error says what to install.
function assertPackagedOrNotFound(output: string): void {
  if (output.startsWith("LOADED ")) {
    assert.ok(isAbsolute(output.slice("LOADED ".length)), output);
  } else {
    assert.match(output, /^ERROR .*was not found/);
    assert.ok(output.includes(`${process.platform} ${process.arch}`), output);
  }
}

test("the library is loaded by absolute path", () => {
  assert.ok(isAbsolute(libraryPath), libraryPath);
  assert.ok(existsSync(libraryPath), libraryPath);
});

for (const layout of ["npm", "pnpm"] as const) {
  test(`the platform package is found in an ${layout} install with nothing set`, () => {
    const root = temporaryDirectory("hide-install-");
    try {
      const { binding, libraries } = install(root, layout);
      const output = probe(NO_OVERRIDE, root, binding);
      assert.ok(
        libraries.some((library) => output === `LOADED ${library}`),
        `${output} is none of ${libraries.join(", ")}`,
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
}

test("a core from another release is refused when the package loads", () => {
  // The installed binding says 0.0.1; the core beside it is the one under test.
  const root = temporaryDirectory("hide-install-");
  try {
    const { binding } = install(root, "npm", "0.0.1");
    const output = probe(NO_OVERRIDE, root, binding);
    assert.match(output, /^ERROR the HIDE native library is version /);
    assert.ok(output.includes("this binding is 0.0.1"), output);
    assert.ok(output.includes("install matching versions"), output);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a library planted where a loader or resolver searches is never loaded", () => {
  // A copy of the real core, so loading it would succeed if anything searched
  // for it: the working directory, PATH, the search paths the Unix loaders
  // honour, and NODE_PATH, which require.resolve consults for a package name.
  const planted = temporaryDirectory("hide-planted-");
  try {
    copyFileSync(libraryPath, join(planted, libraryFile));
    plantPlatformPackages(planted);

    const output = probe(
      {
        ...NO_OVERRIDE,
        NODE_PATH: planted,
        PATH: inFront(planted, "PATH"),
        LD_LIBRARY_PATH: inFront(planted, "LD_LIBRARY_PATH"),
        DYLD_LIBRARY_PATH: inFront(planted, "DYLD_LIBRARY_PATH"),
        DYLD_FALLBACK_LIBRARY_PATH: inFront(planted, "DYLD_FALLBACK_LIBRARY_PATH"),
      },
      planted,
    );
    assert.ok(!output.includes(basename(planted)), output);
    assertPackagedOrNotFound(output);
  } finally {
    rmSync(planted, { recursive: true, force: true });
  }
});

const absentLibrary = join(tmpdir(), "no-such-directory", "hide_ffi_override");

test("HIDE_LIBRARY alone is ignored", () => {
  // One settable variable must not be enough to replace the core. The path
  // does not exist, so honouring it could only show up as a failure naming it.
  for (const optIn of [undefined, "0", "true", "yes", " 1"]) {
    const output = probe({
      HIDE_LIBRARY: absentLibrary,
      HIDE_ALLOW_LIBRARY_OVERRIDE: optIn,
    });
    assert.ok(!output.includes("no-such-directory"), `${String(optIn)}: ${output}`);
    assertPackagedOrNotFound(output);
  }
});

test("HIDE_LIBRARY with the opt-in is what gets loaded", () => {
  const refused = probe({
    HIDE_LIBRARY: absentLibrary,
    HIDE_ALLOW_LIBRARY_OVERRIDE: "1",
  });
  // It is tried, and a failure says so rather than falling back to another copy.
  assert.match(refused, /^ERROR /);
  assert.ok(refused.includes("no-such-directory"), refused);
  assert.ok(refused.includes("could not be loaded"), refused);

  const loaded = probe({ HIDE_LIBRARY: libraryPath, HIDE_ALLOW_LIBRARY_OVERRIDE: "1" });
  assert.equal(loaded, `LOADED ${libraryPath}`);
});

// --- the core and the binding are the same release ---------------------------

test("the loaded core is this binding's version", () => {
  assert.deepEqual(version.split(".").slice(0, 3), BINDING_VERSION.split(".").slice(0, 3));
  checkVersion(version);
});

test("a core of another version is refused", () => {
  for (const [core, binding] of [
    ["0.9.1", "0.9.1"],
    ["1.2.3", "1.2.3"],
    ["0.10.0-rc.1", "0.10.0"],
    ["0.10.0", "0.10.0+build.7"],
  ] as const) {
    checkVersion(core, binding);
  }
  for (const [core, binding] of [
    ["0.9.0", "0.9.1"], // a stale core beside a newer binding
    ["0.9.2", "0.9.1"], // and the reverse
    ["0.10.1", "0.9.1"],
    ["1.9.1", "0.9.1"],
    ["0.9.10", "0.9.1"], // compared as numbers, not as a text prefix
    ["0.91.0", "0.9.10"],
  ] as const) {
    assert.throws(
      () => checkVersion(core, binding),
      /install matching versions/,
      `${core} vs ${binding}`,
    );
  }
  for (const core of ["", "0.9", "v0.9.1", "latest"]) {
    assert.throws(() => checkVersion(core, "0.9.1"), /major\.minor\.patch/, core);
  }
});

// --- packaging ---------------------------------------------------------------

test("the published tarball carries the built package and none of its tests", () => {
  // --ignore-scripts: prepack would rebuild dist underneath the running suite.
  const done = spawnSync("npm pack --dry-run --json --ignore-scripts", {
    cwd: packageRoot,
    shell: true,
    encoding: "utf8",
    timeout: 120_000,
  });
  assert.equal(done.status, 0, done.error?.message ?? done.stderr);
  // npm up to 11 prints an array of packages, npm 12 an object keyed by name.
  type Report = { files: { path: string }[] };
  const parsed = JSON.parse(done.stdout) as Report[] | Record<string, Report>;
  const [report] = Array.isArray(parsed) ? parsed : Object.values(parsed);
  assert.ok(report, done.stdout);
  const files = report.files.map((file) => file.path.replaceAll("\\", "/"));

  for (const required of [
    "package.json",
    "README.md",
    "dist/index.js",
    "dist/index.d.ts",
    "dist/binding.js",
  ]) {
    assert.ok(files.includes(required), `${required} is missing from ${files.join(", ")}`);
  }
  const strays = files.filter((file) => /\.test\.|(^|\/)fixtures\./.test(file));
  assert.deepEqual(strays, []);
});
