#!/usr/bin/env node
// Reference adapter: drives the Rust `hide` CLI (apps/hide-cli) through the
// conformance harness interface documented in conformance/README.md.
//
//   node conformance/harness/adapters/hide-cli.mjs \
//     --verb open-container --input <vector> --key <key file> --out <new path>
//
// It exists so the harness can be exercised against a real, second
// implementation of the format. It is NOT the independent implementation that
// criterion 3 of docs/stability.md asks for: it was written here, and it relays
// the CLI's human-readable error text into the harness's exit-code contract.
// A third party should report the class directly from its own error type
// instead of matching text as this adapter does (docs/stability.md: "CLI
// output text is not stable and should not be parsed").

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

/// The harness's verdict channel (conformance/README.md).
const MALFORMED = 2;
const UNSUPPORTED = 3;
const AUTHENTICATION = 4;
const NO_MATCHING_RECIPIENT = 5;
const NOT_EXPRESSIBLE = 10;

/// `hide`'s error enums as `Display` renders them, in the §6.1 grouping. A
/// reader of this file should treat the strings as the CLI's, not as part of the
/// wire format: they are matched here only because the CLI exits 1 for every
/// refusal.
const CLASSES = [
  // unsupported input: a version, kind, suite, flag or critical key
  [/unsupported HIDE version/, UNSUPPORTED],
  [/unsupported HIDE object kind or flags/, UNSUPPORTED],
  [/unsupported cryptographic suite/, UNSUPPORTED],
  // malformed input: a limit, a wrong length or shape, non-canonical CBOR
  [/unreasonable Argon2 parameters/, MALFORMED],
  [/malformed HIDE header/, MALFORMED],
  [/noncanonical CBOR encoding/, MALFORMED],
  [/invalid file metadata/, MALFORMED],
  [/invalid HIDE container/, MALFORMED],
  [/header length is outside protocol limits/, MALFORMED],
  [/truncated payload/, MALFORMED],
  [/invalid payload record/, MALFORMED],
  [/unexpected bytes after final record/, MALFORMED],
  [/object exceeds the chunk limit/, MALFORMED],
  [/not a HIDE container or key file/, MALFORMED],
  [/is not a HIDE public key/, MALFORMED],
  [/is not a HIDE secret key/, MALFORMED],
  // authentication failure, and the single non-recipient outcome (§6.1)
  [/no matching recipient or invalid header authentication/, NO_MATCHING_RECIPIENT],
  [/cryptographic authentication failed/, AUTHENTICATION],
  [/recipient public key is degenerate/, AUTHENTICATION],
  [/invalid cryptographic parameter/, AUTHENTICATION],
  [/signature does not verify/, AUTHENTICATION],
  [/container is signed but the reader was not asked/, AUTHENTICATION],
  [/container is not signed/, AUTHENTICATION],
];

function parse(argv) {
  const options = { hide: null, verb: null, input: null, key: null, out: null, message: null, vectors: null };
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (value === undefined || !flag.startsWith("--")) {
      usage(`could not parse ${JSON.stringify(flag)}`);
    }
    const name = flag.slice(2);
    if (!Object.hasOwn(options, name)) usage(`unknown flag ${flag}`);
    options[name] = value;
  }
  options.hide ??= join(REPO, "target", "release", process.platform === "win32" ? "hide.exe" : "hide");
  return options;
}

function usage(message) {
  process.stderr.write(`hide-cli adapter: ${message}\n`);
  process.stderr.write(
    `usage: hide-cli.mjs --verb <verb> --input <vector> [--key <file>] [--out <path>] [--hide <binary>]\n`,
  );
  process.exit(2);
}

/// Says "this adapter cannot express the check", which the harness reports as
/// NOT CHECKED with the first stderr line as the reason. Never a pass.
function notExpressible(reason) {
  process.stderr.write(`${reason}\n`);
  process.exit(NOT_EXPRESSIBLE);
}

function invoke(hide, args) {
  const result = spawnSync(hide, ["--experimental", "--quiet", ...args], { encoding: "utf8" });
  if (result.error) {
    process.stderr.write(`could not run ${hide}: ${result.error.message}\n`);
    process.exit(1);
  }
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  return result.status;
}

/// The CLI's own status is only ever 0 or 1, so the class has to come from the
/// message. Anything unrecognised stays exit 1, which the harness reports as a
/// misbehaving command rather than as a verdict.
function verdict(status, stderr) {
  if (status === 0) process.exit(0);
  for (const [pattern, code] of CLASSES) {
    if (pattern.test(stderr)) process.exit(code);
  }
  process.exit(1);
}

function main(argv) {
  const options = parse(argv);
  if (!existsSync(options.hide)) {
    process.stderr.write(`no hide binary at ${options.hide}; build it or pass --hide <path>\n`);
    process.exit(1);
  }
  if (options.verb === "open-container") {
    const status = invoke(options.hide, ["open", "--secret", options.key, "--output", options.out, options.input]);
    return verdict(status, lastStderr);
  }
  if (options.verb === "load-key") {
    const bytes = readFileSync(options.input);
    if (bytes.subarray(0, 8).toString("ascii") === "HIDE-KEY") {
      notExpressible(
        "the key file is passphrase-protected and the CLI reads a passphrase only from a terminal, so it refuses before the header's Argon2 parameters are examined; this check is not expressible through the CLI",
      );
    }
    if (bytes.length !== 32) {
      notExpressible(`a ${bytes.length}-byte key file has no CLI command that loads it`);
    }
    return verdict(invoke(options.hide, ["ssh-key", "--secret", options.input]), lastStderr);
  }
  if (options.verb === "load-public-key") {
    const bytes = readFileSync(options.input);
    if (bytes.length === 1216) {
      // §9.5: a sender must refuse the malformed and small-order encodings, so
      // the probe is "use this file as a recipient".
      const plaintext = `${options.out}.plain`;
      writeFileSync(plaintext, Buffer.alloc(0));
      return verdict(
        invoke(options.hide, ["encrypt", plaintext, "--recipient", options.input, "--output", options.out]),
        lastStderr,
      );
    }
    if (bytes.length === 1984) {
      // A standalone 1984-byte verifying key is only ever loaded by `verify`,
      // which needs a signature file; `info` is the closest the CLI has, and it
      // describes without validating. There is no rejection vector for this
      // shape, so nothing is being skipped — see conformance/README.md.
      return verdict(invoke(options.hide, ["info", options.input]), lastStderr);
    }
    notExpressible(`a ${bytes.length}-byte public key file has no CLI command that loads it`);
  }
  if (options.verb === "verify-subsystem") {
    notExpressible(
      "the CLI exposes replay of an identity log and of an epoch chain, but no command that verifies a standalone head, device, inclusion path, consistency path, checkpoint or MLS binding",
    );
  }
  usage(`unknown verb ${options.verb}`);
  return 1;
}

// `invoke` prints the CLI's stderr straight through, so keep the last one for
// classification.
let lastStderr = "";
const originalWrite = process.stderr.write.bind(process.stderr);
process.stderr.write = (chunk, ...rest) => {
  lastStderr += String(chunk);
  return originalWrite(chunk, ...rest);
};

process.exitCode = main(process.argv.slice(2));
