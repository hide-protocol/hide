import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Loads the HIDE C core. The same shared library serves every binding, so
 * there is exactly one implementation of the cryptography to review.
 */

const require = createRequire(import.meta.url);
// koffi ships prebuilt binaries, so installing this package needs no compiler.
const koffi = require("koffi");

function libraryName(): string {
  if (process.platform === "win32") return "hide_ffi.dll";
  if (process.platform === "darwin") return "libhide_ffi.dylib";
  return "libhide_ffi.so";
}

// Alpine and other musl distributions cannot load a glibc build, and the two
// are indistinguishable from process.platform alone.
function isMusl(): boolean {
  if (process.platform !== "linux") return false;
  const report = process.report?.getReport();
  const header = typeof report === "object" ? (report as { header?: { glibcVersionRuntime?: string } }).header : undefined;
  if (header) return !header.glibcVersionRuntime;
  try {
    return readFileSync("/usr/bin/ldd", "utf8").includes("musl");
  } catch {
    return false;
  }
}

function platformPackage(): string {
  const suffix = isMusl() ? "-musl" : "";
  return `@hide-protocol/${process.platform}-${process.arch}${suffix}`;
}

function locate(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const fromPackage = (() => {
    try {
      return require.resolve(`${platformPackage()}/${libraryName()}`);
    } catch {
      return undefined;
    }
  })();
  const candidates = [
    // Set by developers running against a cargo build tree.
    process.env.HIDE_LIBRARY,
    fromPackage,
    join(here, libraryName()),
    join(here, "..", libraryName()),
    join(here, "..", "native", libraryName()),
  ].filter((path): path is string => Boolean(path));

  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  throw new Error(
    `the HIDE native library (${libraryName()}) was not found. Install a ` +
      `platform package (npm i ${platformPackage()}), or set HIDE_LIBRARY to ` +
      "the path produced by `cargo build -p hide-ffi`.",
  );
}

const lib = koffi.load(locate());

export const Buffer_ = koffi.struct("HideBuffer", {
  data: "uint8_t *",
  len: "size_t",
  capacity: "size_t",
});

const OpaqueKey = koffi.opaque("HideSecretKey");
export const KeyPtr = koffi.pointer(OpaqueKey);

export const OK = 0;
export const ERR_INVALID_ARGUMENT = 1;
export const ERR_WRONG_PASSPHRASE = 2;
export const ERR_NOT_A_KEY = 3;
export const ERR_AUTHENTICATION = 4;
export const ERR_NO_MATCHING_RECIPIENT = 5;
export const ERR_MALFORMED = 6;
export const ERR_TOO_LARGE = 7;
export const ERR_CHALLENGE_EXPIRED = 8;
export const ERR_CHALLENGE_REPLAYED = 9;

export const KEY_PROTECTED = 1;
export const PUBLIC_KEY_LEN = 1216;
export const MIN_PASSPHRASE_LEN = 8;
export const SIGNATURE_LEN = 3373;
export const VERIFYING_KEY_LEN = 1984;
export const NONCE_LEN = 32;

export const fns = {
  version: lib.func("const char *hide_version()"),
  errorMessage: lib.func("const char *hide_error_message(int32_t code)"),
  bufferFree: lib.func("void hide_buffer_free(_Inout_ HideBuffer *buffer)"),

  keypairGenerate: lib.func(
    "int32_t hide_keypair_generate(_Out_ void **secret, _Out_ HideBuffer *public)",
  ),
  inspectKey: lib.func(
    "int32_t hide_inspect_key(const uint8_t *data, size_t len, _Out_ int32_t *kind)",
  ),
  secretKeyOpen: lib.func(
    "int32_t hide_secret_key_open(const uint8_t *data, size_t len, const char *passphrase, _Out_ void **secret)",
  ),
  secretKeyProtect: lib.func(
    "int32_t hide_secret_key_protect(void *secret, const char *passphrase, _Out_ HideBuffer *out)",
  ),
  secretKeyPublic: lib.func(
    "int32_t hide_secret_key_public(void *secret, _Out_ HideBuffer *out)",
  ),
  secretKeyFree: lib.func("void hide_secret_key_free(void *secret)"),

  publicKeyArmor: lib.func(
    "int32_t hide_public_key_armor(const uint8_t *data, size_t len, _Out_ HideBuffer *out)",
  ),
  publicKeyDearmor: lib.func(
    "int32_t hide_public_key_dearmor(const char *text, _Out_ HideBuffer *out)",
  ),

  encrypt: lib.func(
    "int32_t hide_encrypt(const uint8_t *plaintext, size_t plaintext_len, const uint8_t *recipients, size_t recipient_count, const char *filename, const char *media_type, _Out_ HideBuffer *out)",
  ),
  decrypt: lib.func(
    "int32_t hide_decrypt(const uint8_t *container, size_t container_len, void *secret, _Out_ HideBuffer *out, _Out_ HideBuffer *filename, _Out_ HideBuffer *media_type)",
  ),

  identityGenerate: lib.func(
    "int32_t hide_identity_generate(const char *passphrase, _Out_ HideBuffer *out)",
  ),
  signingIdentityOpen: lib.func(
    "int32_t hide_signing_identity_open(const uint8_t *data, size_t len, const char *passphrase, _Out_ void **identity)",
  ),
  signingIdentityPublic: lib.func(
    "int32_t hide_signing_identity_public(void *identity, _Out_ HideBuffer *out)",
  ),
  signingIdentityFree: lib.func("void hide_signing_identity_free(void *identity)"),
  signMessage: lib.func(
    "int32_t hide_sign_message(void *identity, const uint8_t *context, size_t context_len, const uint8_t *message, size_t message_len, _Out_ HideBuffer *out)",
  ),
  verifyMessage: lib.func(
    "int32_t hide_verify_message(const uint8_t *public_key, size_t public_key_len, const uint8_t *context, size_t context_len, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len)",
  ),

  challengeNew: lib.func(
    "int32_t hide_challenge_new(const char *audience, uint64_t now, uint64_t valid_for, _Out_ HideBuffer *out)",
  ),
  challengeAnswer: lib.func(
    "int32_t hide_challenge_answer(void *identity, const uint8_t *challenge, size_t challenge_len, _Out_ HideBuffer *out)",
  ),
  spentNoncesNew: lib.func("void *hide_spent_nonces_new()"),
  spentNoncesFree: lib.func("void hide_spent_nonces_free(void *spent)"),
  challengeAccept: lib.func(
    "int32_t hide_challenge_accept(void *spent, const uint8_t *challenge, size_t challenge_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key, size_t public_key_len, uint64_t now)",
  ),

  identityVerify: lib.func(
    "int32_t hide_identity_verify(const uint8_t *log, size_t log_len, const uint8_t *recovery, size_t recovery_len, _Out_ size_t *devices)",
  ),
  identityTrustsDevice: lib.func(
    "int32_t hide_identity_trusts_device(const uint8_t *log, size_t log_len, const uint8_t *recovery, size_t recovery_len, const uint8_t *device_public, size_t device_public_len, _Out_ int32_t *trusted)",
  ),
  identityHead: lib.func(
    "int32_t hide_identity_head(const uint8_t *log, size_t log_len, const uint8_t *recovery, size_t recovery_len, _Out_ HideBuffer *out)",
  ),

  epochVerify: lib.func(
    "int32_t hide_epoch_verify(const uint8_t *chain, size_t chain_len, _Out_ size_t *epochs)",
  ),
  epochPublicKey: lib.func(
    "int32_t hide_epoch_public_key(const uint8_t *chain, size_t chain_len, uint64_t epoch, _Out_ HideBuffer *out)",
  ),

  transparencyVerifyInclusion: lib.func(
    "int32_t hide_transparency_verify_inclusion(const uint8_t *leaf, size_t leaf_len, uint64_t index, uint64_t size, const uint8_t *path, size_t path_len, const uint8_t *root, size_t root_len)",
  ),
  transparencyVerifyConsistency: lib.func(
    "int32_t hide_transparency_verify_consistency(uint64_t old_size, uint64_t new_size, const uint8_t *path, size_t path_len, const uint8_t *old_root, size_t old_root_len, const uint8_t *new_root, size_t new_root_len)",
  ),
};

export { koffi };
