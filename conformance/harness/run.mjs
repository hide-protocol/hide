#!/usr/bin/env node
// HIDE conformance harness (roadmap to 1.0, criterion 3).
//
// Language-neutral and dependency-free: it drives a command *you* supply once
// per frozen vector and compares the outcome with conformance/compliance.json.
// Nothing here knows how HIDE is implemented, so a Go, Python, Rust or .NET
// implementation can be checked with the same harness.
//
//   node conformance/harness/run.mjs --command "my-hide check {verb} --input {input} --key {key} --output {out}"
//
// The interface, the exit-code verdict channel and what this does *not* prove
// are documented in conformance/README.md. `--help` prints a summary.

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HARNESS_DIR = dirname(fileURLToPath(import.meta.url));
const DEFAULT_VECTORS = resolve(HARNESS_DIR, "..", "vectors");
const DEFAULT_COMPLIANCE = resolve(HARNESS_DIR, "..", "compliance.json");

/// The verdict channel: the command's exit status. Documented in
/// conformance/README.md and mirrored in compliance.json ("protocol").
const EXIT_CLASS = new Map([
  [2, "malformed"],
  [3, "unsupported"],
  [4, "authentication"],
  [5, "no-matching-recipient"],
]);
const NOT_EXPRESSIBLE = 10;
/// Exit statuses that mean "the command itself did not run", not "refused".
const NOT_FOUND_STATUS = new Set([127, 9009]);

/// One verb per manifest `kind` a command can be asked to perform. A command
/// may exit 10 for a verb it does not implement; the harness then reports the
/// vector as NOT CHECKED, never as a pass.
///
/// `detached-signature` has no verb: spec §14 makes the detached-signature file
/// implementation-defined and conformance/vectors/README.md obliges only the
/// recorded sha256, so those vectors are hash-checked here and never driven.
const VERB = new Map([
  ["container", "open-container"],
  ["key", "load-key"],
  ["public-key", "load-public-key"],
  ["subsystem", "verify-subsystem"],
]);
/// Kinds the harness checks itself, with no command.
const SELF_CHECKED = new Set(["detached-signature"]);

const PLACEHOLDERS = ["verb", "input", "key", "out", "message", "vectors"];

const USAGE = `HIDE conformance harness

  node conformance/harness/run.mjs --command "<template>" [options]

  --command <template>   the command that implements HIDE, with placeholders
                         {verb} {input} {key} {out} {message} {vectors}
  --vectors <dir>        vector directory (default: conformance/vectors)
  --compliance <file>    expectation file (default: conformance/compliance.json)
  --timeout <ms>         per-vector timeout (default: 30000)
  --require-complete     treat a vector that could not be checked as a failure
  -h, --help             this text

The command reports its verdict through its exit status:

  0   accepted
  2   refused, malformed          (§6.1)
  3   refused, unsupported        (§6.1)
  4   refused, authentication     (§6.1)
  5   refused, no matching recipient (§6.1, the single non-recipient outcome)
  10  this command does not implement {verb}
  other  the command did not run; the harness treats it as a failure

Interpreting the verdict, the placeholders and what the harness does not prove:
conformance/README.md.`;

class UsageError extends Error {}

function parseArguments(argv) {
  const options = {
    command: null,
    vectors: DEFAULT_VECTORS,
    compliance: DEFAULT_COMPLIANCE,
    timeoutMs: 30000,
    requireComplete: false,
    help: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const value = () => {
      index += 1;
      if (index >= argv.length) throw new UsageError(`missing value after ${argument}`);
      return argv[index];
    };
    if (argument === "--help" || argument === "-h") options.help = true;
    else if (argument === "--command") options.command = value();
    else if (argument === "--vectors") options.vectors = resolve(value());
    else if (argument === "--compliance") options.compliance = resolve(value());
    else if (argument === "--timeout") {
      options.timeoutMs = Number(value());
      if (!Number.isFinite(options.timeoutMs) || options.timeoutMs <= 0) {
        throw new UsageError("--timeout must be a positive number of milliseconds");
      }
    } else if (argument === "--require-complete") options.requireComplete = true;
    else throw new UsageError(`unknown argument ${argument}`);
  }
  return options;
}

/// The command templates arrive as shell command lines, so a substituted path is
/// quoted. Values that a shell would expand even inside quotes are refused
/// rather than silently mangled.
function quoteForShell(value) {
  if (value === "") return '""';
  if (/["$`%]/.test(value)) {
    throw new UsageError(
      `a substituted path contains a character this harness will not hand to a shell: ${value}`,
    );
  }
  return `"${value}"`;
}

function substitute(template, values) {
  return template.replace(/\{([a-z]+)\}/g, (whole, name) => {
    if (!PLACEHOLDERS.includes(name)) return whole;
    return quoteForShell(values[name] ?? "");
  });
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function describeClass(status) {
  if (status === 0) return "accepted";
  const name = EXIT_CLASS.get(status);
  return name ? `refused, ${name}` : `exit ${status}`;
}

function firstLine(text) {
  return String(text).split(/\r?\n/).find((line) => line.trim() !== "") ?? "";
}

/// Writes the plaintext the manifest's sibling `.txt` records, so a command that
/// silently accepted without producing output is caught rather than rewarded.
function plaintextFor(vectors, path) {
  const sibling = join(vectors, path.replace(/\.hide$/, ".txt"));
  return existsSync(sibling) ? readFileSync(sibling) : null;
}

function main(argv) {
  let options;
  try {
    options = parseArguments(argv);
  } catch (error) {
    if (error instanceof UsageError) {
      process.stderr.write(`harness: ${error.message}\n\n${USAGE}\n`);
      return 2;
    }
    throw error;
  }
  if (options.help) {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }

  const manifestPath = join(options.vectors, "manifest.json");
  const index = join(options.vectors, "rejections", "rejections.txt");
  for (const path of [manifestPath, options.compliance, index]) {
    if (!existsSync(path)) {
      process.stderr.write(`harness: cannot read ${path}\n`);
      return 2;
    }
  }

  const manifestBytes = readFileSync(manifestPath);
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  const compliance = readJson(options.compliance);
  const rejectionsIndex = readFileSync(index, "utf8")
    .split(/\r?\n/)
    .filter((line) => line !== "" && !line.startsWith("#"))
    .map((line) => {
      const [name, reason] = line.split("\t");
      return { name, reason };
    });

  const problems = [];
  const note = (message) => problems.push(message);

  // ---- the harness's own invariants, checked before any command runs -------
  process.stdout.write(`HIDE conformance harness\n`);
  process.stdout.write(`  vectors     ${options.vectors}\n`);
  process.stdout.write(`  compliance  ${options.compliance}\n`);

  if (manifest.format !== "hide-vectors/1") {
    note(`manifest.json format is ${JSON.stringify(manifest.format)}, expected "hide-vectors/1"`);
  }
  if (compliance.compliance !== "hide-conformance/1") {
    note(`compliance.json is ${JSON.stringify(compliance.compliance)}, expected "hide-conformance/1"`);
  }
  const manifestHash = sha256(manifestBytes);
  const recordedHash = compliance.vectors?.manifestSha256;
  if (recordedHash !== manifestHash) {
    note(
      `compliance.json records manifest sha256 ${recordedHash}, but the manifest here hashes to ${manifestHash}`,
    );
  }
  process.stdout.write(
    `  manifest    ${manifest.vectors.length} vectors, sha256 ${manifestHash}` +
      `${recordedHash === manifestHash ? " (matches compliance.json)" : " (MISMATCH)"}\n`,
  );

  const expectations = compliance.expected ?? {};
  for (const entry of manifest.vectors) {
    if (!Object.hasOwn(expectations, entry.path)) {
      note(`compliance.json has no expectation for ${entry.path}`);
    }
  }
  for (const path of Object.keys(expectations)) {
    if (!manifest.vectors.some((entry) => entry.path === path)) {
      note(`compliance.json expects ${path}, which the manifest does not list`);
    }
  }

  // rejections.txt and the manifest must name the same files, so a rejection
  // cannot be added to one and forgotten in the other.
  const manifestRejections = new Set(
    manifest.vectors.filter((entry) => entry.path.startsWith("rejections/")).map((entry) => entry.path),
  );
  for (const { name, reason } of rejectionsIndex) {
    const listing = manifest.vectors.find((entry) => entry.path === `rejections/${name}` ||
      entry.path === `rejections/${name}.hide`);
    if (!listing) {
      note(`rejections.txt lists ${name}, which the manifest does not`);
      continue;
    }
    if (listing.expect !== "reject") note(`rejections.txt lists ${name}, but the manifest expects ${listing.expect}`);
    if (reason === undefined || reason.trim() === "") note(`rejections.txt gives ${name} no reason`);
  }
  for (const path of manifestRejections) {
    // The index names an entry either with its own extension
    // (`small-order.test-public`) or without one at all
    // (`bad-magic` for `bad-magic.hide`), so the lookup mirrors the forward
    // check above rather than comparing the bare basename.
    const file = path.slice("rejections/".length);
    const listed = rejectionsIndex.some(
      ({ name }) => name === file || `${name}.hide` === file,
    );
    if (!listed) {
      note(`${path} is a rejection vector that rejections.txt does not list`);
    }
  }
  process.stdout.write(
    `  rejections  ${rejectionsIndex.length} listed, ${manifestRejections.size} in the manifest\n`,
  );

  // ---- the vector set ------------------------------------------------------
  const hashes = new Map();
  for (const entry of manifest.vectors) {
    const file = join(options.vectors, entry.path);
    if (!existsSync(file)) {
      note(`vector file is missing: ${entry.path}`);
      continue;
    }
    const bytes = readFileSync(file);
    const actual = sha256(bytes);
    hashes.set(entry.path, actual === String(entry.sha256).toLowerCase());
    if (!hashes.get(entry.path)) {
      note(`${entry.path} hashes to ${actual}, manifest records ${entry.sha256}`);
    }
  }
  const hashFailures = [...hashes.values()].filter((ok) => !ok).length;
  process.stdout.write(`  hashes      ${hashes.size - hashFailures}/${hashes.size} vectors match the manifest\n`);

  if (problems.length > 0) {
    process.stdout.write(`\nThe vector set and compliance.json do not agree; no command was run:\n`);
    for (const problem of problems) process.stdout.write(`  ${problem}\n`);
    return 2;
  }

  // ---- drive the vectors ---------------------------------------------------
  const work = mkdtempSync(join(tmpdir(), "hide-harness-"));
  const lines = [];
  const notChecked = [];
  let checked = 0;
  let failed = 0;
  const checkedByKind = new Map();

  const record = (kind) => checkedByKind.set(kind, (checkedByKind.get(kind) ?? 0) + 1);

  try {
    for (const [position, entry] of manifest.vectors.entries()) {
      const expectation = expectations[entry.path];
      const verb = VERB.get(entry.kind);
      const selfChecked = SELF_CHECKED.has(entry.kind);
      // A passphrase-protected key file cannot be driven through the verb set:
      // `load-key` takes a filename and nothing else, and an implementation
      // MUST NOT accept a passphrase from anything but a terminal (§15.5). Its
      // bytes are hash-pinned like an implementation-defined artifact, and the
      // passphrase is recorded in compliance.json so an implementer can open it
      // in their own suite.
      const passphraseProtected = expectation.passphrase !== undefined;
      const hashOnly = selfChecked || passphraseProtected;
      const label = `${entry.kind} ${entry.expect}`;
      if (verb === undefined && !hashOnly) {
        lines.push(`FAIL  ${entry.path} — unknown kind ${entry.kind}`);
        failed += 1;
        continue;
      }

      // The declared outcome must be one of the two the format defines.
      if (entry.expect !== "open" && entry.expect !== "reject") {
        lines.push(`FAIL  ${entry.path} — manifest expect is ${JSON.stringify(entry.expect)}`);
        failed += 1;
        continue;
      }
      if (expectation.expect !== entry.expect) {
        lines.push(
          `FAIL  ${entry.path} — compliance.json expects ${expectation.expect}, the manifest says ${entry.expect}`,
        );
        failed += 1;
        continue;
      }

      const output = join(work, `${position}-${basename(entry.path)}.out`);

      // An implementation-defined artifact (spec §14): conformance/vectors/
      // README.md obliges only the recorded hash here, and `cargo test
      // -p hide-sign --test vectors` is what pins byte-for-byte reproduction.
      // Nothing is driven for this kind.
      if (hashOnly) {
        checked += 1;
        record(entry.kind);
        const why = selfChecked
          ? "hash-only: implementation-defined, §14"
          : "hash-only: passphrase-protected, no verb takes a passphrase";
        lines.push(`PASS  ${entry.path} — ${label}, sha256 (${why})`);
        continue;
      }

      if (options.command === null) {
        notChecked.push({ path: entry.path, kind: entry.kind, reason: "no --command was supplied" });
        continue;
      }

      const keyPath =
        entry.kind === "container"
          ? join(options.vectors, expectation.key ?? manifest.secret)
          : join(options.vectors, entry.path);

      const command = substitute(options.command, {
        verb,
        input: join(options.vectors, entry.path),
        key: keyPath,
        out: output,
        message: "",
        vectors: options.vectors,
      });

      const result = spawnSync(command, {
        shell: true,
        encoding: "utf8",
        timeout: options.timeoutMs,
        windowsHide: true,
        maxBuffer: 8 * 1024 * 1024,
      });
      const status = result.status;

      if (result.error || status === null) {
        const why = result.error?.code === "ETIMEDOUT" ? `timed out after ${options.timeoutMs} ms` : `was killed (${result.signal ?? result.error?.code})`;
        lines.push(`FAIL  ${entry.path} — the command ${why}\n        ${command}`);
        failed += 1;
        continue;
      }
      if (NOT_FOUND_STATUS.has(status)) {
        process.stdout.write(`\nharness: the command did not run (exit ${status}). Check --command:\n  ${command}\n`);
        return 2;
      }
      if (status === NOT_EXPRESSIBLE) {
        notChecked.push({
          path: entry.path,
          kind: entry.kind,
          reason: firstLine(result.stderr) || firstLine(result.stdout) || "the command declined the verb",
        });
        continue;
      }
      if (!EXIT_CLASS.has(status) && status !== 0) {
        lines.push(
          `FAIL  ${entry.path} — exit ${status} is not a verdict; a refusal must be 2 malformed, 3 unsupported, 4 authentication or 5 no-matching-recipient\n        ${firstLine(result.stderr)}`,
        );
        failed += 1;
        continue;
      }

      if (entry.expect === "open") {
        if (status !== 0) {
          lines.push(`FAIL  ${entry.path} — expected open, observed ${describeClass(status)}`);
          failed += 1;
          continue;
        }
        let detail = "";
        if (entry.kind === "container") {
          const expected = plaintextFor(options.vectors, entry.path);
          if (expected === null) {
            detail = " (no recorded plaintext to compare)";
          } else if (!existsSync(output)) {
            lines.push(`FAIL  ${entry.path} — accepted but wrote no plaintext to {out}`);
            failed += 1;
            continue;
          } else {
            const actual = readFileSync(output);
            if (!actual.equals(expected)) {
              lines.push(
                `FAIL  ${entry.path} — accepted, but the plaintext differs (${actual.length} bytes, expected ${expected.length})`,
              );
              failed += 1;
              continue;
            }
            detail = ` (${actual.length}-byte plaintext matches the recorded .txt)`;
          }
        }
        checked += 1;
        record(entry.kind);
        lines.push(`PASS  ${entry.path} — ${label}${detail}`);
        continue;
      }

      // expect === "reject"
      const allowed = expectation.classes ?? [];
      if (status === 0) {
        lines.push(`FAIL  ${entry.path} — expected reject, observed accepted`);
        failed += 1;
        continue;
      }
      const observed = EXIT_CLASS.get(status);
      if (allowed.length > 0 && !allowed.includes(observed)) {
        lines.push(
          `FAIL  ${entry.path} — refused as ${observed}, expected ${allowed.join(" or ")}`,
        );
        failed += 1;
        continue;
      }
      if (entry.kind === "container" && existsSync(output)) {
        lines.push(
          `FAIL  ${entry.path} — refused as ${observed} but published plaintext (spec §5: "MUST NOT publish plaintext before the FINAL record authenticates")`,
        );
        failed += 1;
        continue;
      }
      checked += 1;
      record(entry.kind);
      lines.push(`PASS  ${entry.path} — ${label}, ${observed}`);
    }
  } finally {
    rmSync(work, { recursive: true, force: true });
  }

  for (const line of lines) process.stdout.write(`${line}\n`);

  // ---- the verdict ---------------------------------------------------------
  process.stdout.write(`\nPASS ${checked}/${checked}\n`);
  const kinds = [...checkedByKind].map(([kind, n]) => `${kind} ${n}`).join(", ");
  if (kinds !== "") process.stdout.write(`  checked: ${kinds}\n`);
  if (failed > 0) process.stdout.write(`FAIL ${failed}\n`);

  if (notChecked.length > 0) {
    const byKind = new Map();
    for (const item of notChecked) {
      if (!byKind.has(item.kind)) byKind.set(item.kind, []);
      byKind.get(item.kind).push(item);
    }
    process.stdout.write(
      `NOT CHECKED ${notChecked.length} (${[...byKind].map(([kind, items]) => `${kind} ${items.length}`).join(", ")})\n`,
    );
    for (const [kind, items] of byKind) {
      const reasons = [...new Set(items.map((item) => item.reason))].slice(0, 2);
      process.stdout.write(`  ${kind}: ${items.map((item) => item.path).slice(0, 3).join(", ")}${items.length > 3 ? ", …" : ""}\n`);
      for (const reason of reasons) process.stdout.write(`    ${reason}\n`);
    }
    process.stdout.write(
      `  A vector that could not be checked is never a pass. This is not a conformance claim:\n` +
        `  see conformance/README.md and criteria in conformance/compliance.json.\n`,
    );
  }

  if (failed > 0) return 1;
  if (notChecked.length > 0 && options.requireComplete) {
    process.stdout.write(`--require-complete: ${notChecked.length} vector(s) could not be checked\n`);
    return 3;
  }
  return 0;
}

process.exitCode = main(process.argv.slice(2));
