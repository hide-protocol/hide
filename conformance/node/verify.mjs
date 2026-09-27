// Independent HIDE/1.0 container reader and writer (spec/hide-1.md §1–§7).
//
// Nothing here calls the Rust crates: the preamble, protected header, stanza
// grammar, metadata rules, key schedule, record stream and both signature
// transcripts are re-derived from the specification, so a disagreement with the
// Rust implementation shows up as a failing vector rather than as two copies of
// the same bug.
//
// Run directly (`node verify.mjs`) it checks every frozen vector. Imported, it
// exposes `decrypt`, `encrypt` and `rebuild` so a differential fuzzer can build
// fully re-MACed, re-encrypted mutants that reach the checks behind the MAC.

import assert from "node:assert/strict";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPublicKey,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  sign as nodeSign,
  timingSafeEqual,
  verify as nodeVerify,
} from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CipherSuite, HkdfSha256 } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { XWing } from "@hpke/hybridkem-x-wing";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import cbor from "cbor";
import { verifySubsystems } from "./subsystems.mjs";

const magic = Buffer.from("484944450d0a1a0a", "hex");
const SUITE = 1;
const suiteBytes = Buffer.from([0, 1]);
const kem = new XWing();
const suite = new CipherSuite({ kem, kdf: new HkdfSha256(), aead: new Chacha20Poly1305() });
const concat = (...parts) => Buffer.concat(parts.map((part) => Buffer.from(part)));
const label = (value) => Buffer.from(`HIDE/0.1 ${value}`, "ascii");
const hash = (value) => createHash("sha256").update(value).digest();
const derive = (cek, salt, info) => Buffer.from(hkdfSync("sha256", cek, salt, info, 32));

const MAX_HEADER_LEN = 1024 * 1024;
const MAX_STANZAS = 64;
const MAX_STANZA_ITEMS = 8;
const MAX_FIELD_LEN = 65536;
const MAX_EXTENSIONS = 16;
const MAX_METADATA_LEN = 262144;
const TAG_LEN = 16;
const XWING_TAG = 1;
const ENCAPSULATION_LEN = 1120;
const WRAPPED_CEK_LEN = 48;
const FLAG_SIGNED = 0x01;
const KNOWN_FLAGS = FLAG_SIGNED;
const LEGACY_MINOR = 2;

const VERIFYING_KEY_LEN = 1984;
const SIGNATURE_LEN = 3373;
const CONTEXT_1_0 = Buffer.from("HIDE/1.0 container", "ascii");
const TRANSCRIPT_1_0 = Buffer.from("HIDE/1.0 transcript", "ascii");
const CONTEXT_LEGACY = Buffer.from("HIDE/0.5 container", "ascii");
const TRANSCRIPT_LEGACY = Buffer.from("HIDE/0.5 transcript", "ascii");

/// A refusal carrying the spec's error class, so a self-test can show a
/// container failed for the intended rule and not for an unrelated one.
export class Rejection extends Error {
  constructor(code, detail) {
    super(detail ? `${code}: ${detail}` : code);
    this.code = code;
  }
}
const reject = (code, detail) => {
  throw new Rejection(code, detail);
};
const need = (condition, code, detail) => {
  if (!condition) reject(code, detail);
};

// Deterministic CBOR (RFC 8949 §4.2.1) for the subset HIDE uses: uint, bstr,
// tstr, array and Map, shortest-form heads, map keys sorted bytewise by their
// encoding. Written here rather than taken from the `cbor` package, whose
// encoders are unusable for this: encodeCanonical/encodeOne truncate Maps and
// arrays to one byte, and encodeAsync({canonical:true}) leaves Map keys
// wider than one byte (e.g. 0xFAFA) in insertion order.
function cborHead(major, value) {
  const n = BigInt(value);
  assert.ok(n >= 0n && n < 1n << 64n, "CBOR argument out of range");
  if (n < 24n) return Buffer.from([(major << 5) | Number(n)]);
  const width = n < 1n << 8n ? 1 : n < 1n << 16n ? 2 : n < 1n << 32n ? 4 : 8;
  const out = Buffer.alloc(1 + width);
  out[0] = (major << 5) | { 1: 24, 2: 25, 4: 26, 8: 27 }[width];
  for (let i = width, v = n; i >= 1; i--, v >>= 8n) out[i] = Number(v & 0xffn);
  return out;
}

export function encodeCbor(value) {
  if (typeof value === "number" || typeof value === "bigint") return cborHead(0, value);
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return concat(cborHead(2, value.length), value);
  if (typeof value === "string") {
    const bytes = Buffer.from(value, "utf8");
    return concat(cborHead(3, bytes.length), bytes);
  }
  if (Array.isArray(value)) return concat(cborHead(4, value.length), ...value.map(encodeCbor));
  if (value instanceof Map) {
    const entries = [...value].map(([k, v]) => [encodeCbor(k), encodeCbor(v)]).sort(([a], [b]) => Buffer.compare(a, b));
    return concat(cborHead(5, entries.length), ...entries.flat());
  }
  throw new TypeError(`cannot CBOR-encode ${typeof value}`);
}
const encode = async (value) => encodeCbor(value);

function uint16(value) {
  const bytes = Buffer.alloc(2);
  bytes.writeUInt16BE(value);
  return bytes;
}

function uint32(value) {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value);
  return bytes;
}

function uint64(value) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(BigInt(value));
  return bytes;
}

// ---------------------------------------------------------------------------
// HIDE-Sign (§8): Ed25519 with verify_strict semantics + ML-DSA-65
// ---------------------------------------------------------------------------

const ED25519_SPKI = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_L = (1n << 252n) + 27742317777372353535851937790883648493n;

// libsodium's ge25519_has_small_order blocklist. Compared on bytes 0..30 plus
// byte 31 with the sign bit masked, so the sign-flipped encodings match too.
// node:crypto verifies cofactorless and ACCEPTS small-order A and R, so this
// list is the whole of the strictness; it is what ed25519-dalek verify_strict
// refuses.
const SMALL_ORDER_ED25519 = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
].map((value) => Buffer.from(value, "hex"));

function hasSmallOrder(point) {
  return SMALL_ORDER_ED25519.some((blocked) => {
    let diff = 0;
    for (let i = 0; i < 31; i++) diff |= point[i] ^ blocked[i];
    diff |= (point[31] & 0x7f) ^ blocked[31];
    return diff === 0;
  });
}

function littleEndian(bytes) {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) value = (value << 8n) | BigInt(bytes[i]);
  return value;
}

function ed25519Strict(publicKey, signature, message) {
  if (hasSmallOrder(publicKey)) return false;
  if (hasSmallOrder(signature.subarray(0, 32))) return false;
  if (littleEndian(signature.subarray(32, 64)) >= ED25519_L) return false;
  try {
    const key = createPublicKey({ key: concat(ED25519_SPKI, publicKey), format: "der", type: "spki" });
    return nodeVerify(null, message, key, signature);
  } catch {
    return false;
  }
}

/// hide-sign `bind`: the payload both halves sign.
function bindContext(context, message) {
  return concat(uint64(context.length), context, message);
}

function verifyHybrid(verifyingKey, signature, payload) {
  // Both halves are evaluated before deciding; neither alone is accepted.
  const classical = ed25519Strict(verifyingKey.subarray(0, 32), signature.subarray(0, 64), payload);
  let quantum = false;
  try {
    quantum = ml_dsa65.verify(signature.subarray(64), payload, verifyingKey.subarray(32));
  } catch {
    quantum = false;
  }
  return classical && quantum;
}

/// A throwaway hybrid signing identity for self-tests and the fuzzer. Not the
/// §8.2 seed derivation: that is exercised against the Rust vectors in
/// subsystems.mjs; here only the signature layout matters.
export function newSigningIdentity() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const edPublic = publicKey.export({ format: "der", type: "spki" }).subarray(ED25519_SPKI.length);
  const pq = ml_dsa65.keygen(randomBytes(32));
  return {
    verifyingKey: concat(edPublic, pq.publicKey),
    sign: (payload) => concat(nodeSign(null, payload, privateKey), ml_dsa65.sign(payload, pq.secretKey)),
  };
}

// ---------------------------------------------------------------------------
// Transcripts (§7.2, §7.4)
// ---------------------------------------------------------------------------

/// §7.2. `headerExtensions` is [[key, value]] in ascending key order.
export function transcript10({ preamble12, objectId, stanzas, headerExtensions, metadataBase, plaintext }) {
  const stanzaParts = stanzas.flatMap((stanza) => {
    const fields = stanza.slice(1);
    return [uint64(stanza[0]), uint64(fields.length), ...fields.flatMap((field) => [uint64(field.length), field])];
  });
  const extensionParts = headerExtensions.flatMap(([key, value]) => [uint16(key), uint64(value.length), value]);
  return concat(
    TRANSCRIPT_1_0,
    preamble12,
    suiteBytes,
    objectId,
    uint64(stanzas.length),
    ...stanzaParts,
    uint64(headerExtensions.length),
    ...extensionParts,
    uint64(metadataBase.length),
    metadataBase,
    hash(plaintext),
    uint64(plaintext.length),
  );
}

/// §7.4, the read-only HIDE/0.5 transcript used by minor 2.
export function transcriptLegacy({ objectId, stanzas, metadataBase, plaintext }) {
  return concat(
    TRANSCRIPT_LEGACY,
    suiteBytes,
    objectId,
    uint64(stanzas.length),
    // The reader only reaches this with X-Wing stanzas; slice(1) lets the
    // writer sign a (deliberately invalid) legacy container with unknown ones.
    ...stanzas.flatMap((stanza) => stanza.slice(1)),
    uint64(metadataBase.length),
    metadataBase,
    hash(plaintext),
    uint64(plaintext.length),
  );
}

// ---------------------------------------------------------------------------
// Decoding helpers
// ---------------------------------------------------------------------------

/// Decodes exactly one CBOR item and refuses it unless re-encoding reproduces
/// the input byte for byte. The canonical encoder sorts integer map keys
/// ascending, so this also enforces key order and minimal-length integers.
async function decodeCanonical(bytes, code) {
  let values;
  try {
    values = cbor.decodeAllSync(bytes, { preferMap: true, preventDuplicateKeys: true, max_depth: 16 });
  } catch (error) {
    reject(code, `CBOR: ${error.message}`);
  }
  need(values.length === 1, code, "not exactly one CBOR item");
  let reencoded;
  try {
    reencoded = await encode(values[0]);
  } catch (error) {
    reject(code, `re-encode: ${error.message}`);
  }
  need(reencoded.equals(Buffer.from(bytes)), "NonCanonical", "re-encoding differs");
  return values[0];
}

const isUint = (value) => typeof value === "number" && Number.isInteger(value) && value >= 0;
const isKeyAbove = (value, limit) => (typeof value === "bigint" && value > BigInt(limit)) || (isUint(value) && value > limit);
const isBytes = (value) => Buffer.isBuffer(value);

/// §2.3: [1, verifying_key(1984), signature(3373)]; never skipped.
function checkSignatureStanza(stanza) {
  need(
    Array.isArray(stanza) &&
      stanza.length === 3 &&
      stanza[0] === 1 &&
      isBytes(stanza[1]) &&
      stanza[1].length === VERIFYING_KEY_LEN &&
      isBytes(stanza[2]) &&
      stanza[2].length === SIGNATURE_LEN,
    "UnsupportedFeature",
    "signature stanza tag or shape",
  );
}

/// §2.2. Returns true for an X-Wing stanza, false for an unknown one.
function checkRecipientStanza(stanza) {
  need(Array.isArray(stanza) && stanza.length >= 1 && stanza.length <= MAX_STANZA_ITEMS, "MalformedHeader", "stanza length");
  const tag = stanza[0];
  need(isUint(tag) && tag >= 1 && tag <= 65535, "MalformedHeader", "stanza tag");
  for (const field of stanza.slice(1)) {
    need(isBytes(field) && field.length <= MAX_FIELD_LEN, "MalformedHeader", "stanza field");
  }
  if (tag !== XWING_TAG) return false;
  need(
    stanza.length === 3 && stanza[1].length === ENCAPSULATION_LEN && stanza[2].length === WRAPPED_CEK_LEN,
    "MalformedHeader",
    "X-Wing stanza shape",
  );
  return true;
}

/// §2 + §2.1. Returns the parsed fields and the ignorable extensions.
function checkHeader(header) {
  need(header instanceof Map, "MalformedHeader", "protected is not a map");
  const keys = [...header.keys()];
  need(keys.length >= 5 && keys.slice(0, 5).every((key, i) => key === i + 1), "MalformedHeader", "keys 1..5 required in order");
  need(header.get(1) === SUITE, "UnsupportedSuite");
  const objectId = header.get(2);
  need(isBytes(objectId) && objectId.length === 32, "MalformedHeader", "object_id");
  const stanzas = header.get(3);
  need(Array.isArray(stanzas) && stanzas.length >= 1 && stanzas.length <= MAX_STANZAS, "MalformedHeader", "stanza count");
  const encryptedMetadata = header.get(4);
  need(
    isBytes(encryptedMetadata) && encryptedMetadata.length >= TAG_LEN && encryptedMetadata.length <= MAX_METADATA_LEN + TAG_LEN,
    "MalformedHeader",
    "encrypted_metadata",
  );
  const publicSignatures = header.get(5);
  need(Array.isArray(publicSignatures), "MalformedHeader", "key 5 is not an array");
  need(publicSignatures.length <= 1, "MalformedHeader", "more than one signature stanza");
  publicSignatures.forEach(checkSignatureStanza);
  const xwing = stanzas.map(checkRecipientStanza);

  const extensions = [];
  let previous = 5;
  for (const key of keys.slice(5)) {
    need(isUint(key) || typeof key === "bigint", "MalformedHeader", "non-integer header key");
    need(!isKeyAbove(key, 65535), "MalformedHeader", "header key > 65535");
    need(key > previous, "MalformedHeader", "header keys not ascending");
    previous = key;
    need(key >= 64, "UnsupportedFeature", `critical header key ${key}`);
    const value = header.get(key);
    need(isBytes(value) && value.length <= MAX_FIELD_LEN, "MalformedHeader", `header extension ${key} value`);
    extensions.push([key, value]);
  }
  need(extensions.length <= MAX_EXTENSIONS, "MalformedHeader", "too many header extensions");
  return { objectId, stanzas, xwing, encryptedMetadata, publicSignatures, extensions };
}

const WINDOWS_RESERVED = new Set(["CON", "PRN", "AUX", "NUL"]);

/// §4 filename: one portable path component. Mirrors hide-format
/// validate_filename, which refuses to write anything else.
export function filenameIsPortable(name) {
  const bytes = Buffer.byteLength(name, "utf8");
  if (bytes < 1 || bytes > 255) return false;
  if (name === "." || name === "..") return false;
  if (name.endsWith(".") || name.endsWith(" ")) return false;
  // Rust char::is_control = Unicode Cc: C0, DEL and C1.
  if (/[\u0000-\u001f\u007f-\u009f<>:"/\\|?*]/u.test(name)) return false;
  // ASCII-only uppercase, as to_ascii_uppercase: String#toUpperCase would map
  // e.g. U+017F to "S" and diverge from the Rust rule.
  const stem = name.split(".")[0].replace(/[a-z]/g, (c) => c.toUpperCase());
  if (WINDOWS_RESERVED.has(stem)) return false;
  if (Buffer.byteLength(stem, "utf8") === 4 && /^(COM|LPT)[1-9]$/.test(stem)) return false;
  return true;
}

export function mediaTypeIsValid(value) {
  const bytes = Buffer.from(value, "utf8");
  return bytes.length >= 1 && bytes.length <= 255 && bytes.every((b) => b >= 32 && b <= 126);
}

/// §4. Returns the metadata extensions in ascending order.
function checkMetadata(metadata) {
  need(metadata instanceof Map, "InvalidMetadata", "metadata is not a map");
  const extensions = [];
  let previous = 0;
  for (const [key, value] of metadata) {
    need(isUint(key) || typeof key === "bigint", "InvalidMetadata", "non-integer metadata key");
    need(!isKeyAbove(key, 65535), "InvalidMetadata", "metadata key > 65535");
    need(key > previous, "InvalidMetadata", "metadata keys not ascending (or key 0)");
    previous = key;
    if (key === 1) {
      need(typeof value === "string" && filenameIsPortable(value), "InvalidMetadata", "filename");
    } else if (key === 2) {
      need(typeof value === "string" && mediaTypeIsValid(value), "InvalidMetadata", "media_type");
    } else if (key === 3) {
      checkSignatureStanza(value);
    } else if (key < 64) {
      reject("UnsupportedFeature", `${key <= 5 ? "reserved" : "critical"} metadata key ${key}`);
    } else {
      need(isBytes(value) && value.length <= MAX_FIELD_LEN, "InvalidMetadata", `metadata extension ${key} value`);
      extensions.push([key, value]);
    }
  }
  need(extensions.length <= MAX_EXTENSIONS, "InvalidMetadata", "too many metadata extensions");
  return extensions;
}

// ---------------------------------------------------------------------------
// Container primitives
// ---------------------------------------------------------------------------

function aeadOpen(key, nonce, aad, ciphertext) {
  need(ciphertext.length >= TAG_LEN, "AuthenticationFailed", "ciphertext shorter than tag");
  try {
    const decipher = createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
    decipher.setAAD(aad);
    decipher.setAuthTag(ciphertext.subarray(-16));
    return concat(decipher.update(ciphertext.subarray(0, -16)), decipher.final());
  } catch {
    reject("AuthenticationFailed", "AEAD tag");
  }
}

function aeadSeal(key, nonce, aad, plaintext) {
  const cipher = createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  return concat(cipher.update(plaintext), cipher.final(), cipher.getAuthTag());
}

function chunkContext(objectId, protectedBytes, counter, kind, length) {
  const nonce = Buffer.alloc(12);
  nonce.writeBigUInt64BE(BigInt(counter), 3);
  nonce[11] = kind === 2 ? 1 : 0;
  const aad = concat(label("chunk"), objectId, hash(protectedBytes), uint64(counter), [kind], uint32(length));
  return { nonce, aad };
}

const metadataAad = (objectId) => concat(label("metadata"), objectId, suiteBytes);

/// §9.1: recipient_seed = HKDF-Expand(PRK = m, "HIDE/0.5 identity encryption", 32).
/// Expand only, no Extract; one HMAC block covers L = 32.
export function recipientSeedFromMaster(master) {
  return createHmac("sha256", master).update(concat(Buffer.from("HIDE/0.5 identity encryption", "ascii"), [1])).digest();
}

/// Opens a container with a 32-byte X-Wing recipient seed. Throws a
/// `Rejection` (or an assertion) on anything the spec refuses; returns only
/// after FINAL and, when signed, the signature have verified.
///
/// No whole-container size cap: the Rust reader streams and has none, and the
/// caller has already materialised `container`. Every declared length is still
/// bounded before it is used.
export async function decrypt(container, privateSeed) {
  container = Buffer.from(container);
  need(container.length >= 16, "InvalidContainer", "shorter than the preamble");
  const preamble = container.subarray(0, 16);
  need(preamble.subarray(0, 8).equals(magic), "InvalidContainer", "magic");
  const [major, minor, kind, flags] = preamble.subarray(8, 12);
  need(major === 0, "UnsupportedVersion", `major ${major}`);
  need(minor !== 0, "UnsupportedVersion", "minor 0");
  need(kind === 1, "UnsupportedFeature", `kind ${kind}`);
  need((flags & ~KNOWN_FLAGS) === 0, "UnsupportedFeature", `unknown flag bits ${flags}`);
  const legacy = minor === LEGACY_MINOR;
  need(!legacy || flags === 0, "UnsupportedFeature", "minor 2 with flags");
  const signed = legacy || (flags & FLAG_SIGNED) !== 0;
  const headerLength = preamble.readUInt32BE(12);
  need(headerLength > 0 && headerLength <= MAX_HEADER_LEN, "HeaderTooLarge");
  const headerEnd = 16 + headerLength;
  need(headerEnd + 16 <= container.length, "InvalidContainer", "truncated header or salt");

  const envelope = await decodeCanonical(container.subarray(16, headerEnd), "MalformedHeader");
  need(Array.isArray(envelope) && envelope.length === 2, "MalformedHeader", "header is not array(2)");
  const [protectedBytes, headerMac] = envelope;
  need(isBytes(protectedBytes) && isBytes(headerMac) && headerMac.length === 32, "MalformedHeader", "header items");
  const header = checkHeader(await decodeCanonical(protectedBytes, "MalformedHeader"));
  const { objectId, stanzas, xwing, publicSignatures } = header;
  if (legacy) {
    need(header.extensions.length === 0, "MalformedHeader", "minor 2 with header extensions");
    need(xwing.every(Boolean), "MalformedHeader", "minor 2 with unknown stanzas");
  }

  const secret = await kem.deserializePrivateKey(privateSeed);
  let cek;
  for (const [i, stanza] of stanzas.entries()) {
    if (!xwing[i]) continue;
    try {
      const context = await suite.createRecipientContext({ recipientKey: secret, enc: stanza[1], info: concat(label("object-key"), objectId, suiteBytes) });
      const candidate = Buffer.from(await context.open(stanza[2], concat(objectId, suiteBytes)));
      if (candidate.length !== 32) continue;
      const macKey = derive(candidate, objectId, label("header-mac"));
      const expectedMac = createHmac("sha256", macKey).update(preamble).update(protectedBytes).digest();
      if (timingSafeEqual(expectedMac, headerMac)) {
        cek = candidate;
        break;
      }
    } catch {
      continue;
    }
  }
  need(cek, "NoMatchingRecipient");

  const metadataBytes = aeadOpen(derive(cek, objectId, label("metadata")), Buffer.alloc(12), metadataAad(objectId), header.encryptedMetadata);
  need(metadataBytes.length <= MAX_METADATA_LEN, "InvalidMetadata", "metadata too large");
  const metadata = await decodeCanonical(metadataBytes, "InvalidMetadata");
  const metadataExtensions = checkMetadata(metadata);
  if (legacy) need(metadataExtensions.length === 0, "MalformedHeader", "minor 2 with metadata extensions");

  // Signature obligations that do not need the plaintext are decided before
  // any record is opened.
  const confidential = metadata.get(3);
  need(!(publicSignatures.length > 0 && confidential), "InvalidSignature", "signatures in both places");
  const stanza = publicSignatures[0] ?? confidential;
  if (signed) need(stanza, "InvalidSignature", "signed but no signature (stripped)");
  else need(!stanza, "InvalidSignature", "signature present but container is unsigned");

  const key = derive(cek, container.subarray(headerEnd, headerEnd + 16), concat(label("payload"), objectId));
  let offset = headerEnd + 16;
  const plaintext = [];
  for (let counter = 0; counter < 2 ** 32; counter++) {
    need(offset + 5 <= container.length, "TruncatedPayload", "missing FINAL");
    const recordKind = container[offset];
    const length = container.readUInt32BE(offset + 1);
    need(length >= 16 && length <= 65552, "InvalidContainer", "record length");
    need(
      recordKind === 1 ? length === 65552 : recordKind === 2 && (length > 16 || counter === 0),
      "InvalidContainer",
      "record kind/length",
    );
    need(offset + 5 + length <= container.length, "TruncatedPayload", "record truncated");
    const context = chunkContext(objectId, protectedBytes, counter, recordKind, length - 16);
    plaintext.push(aeadOpen(key, context.nonce, context.aad, container.subarray(offset + 5, offset + 5 + length)));
    offset += 5 + length;
    if (recordKind !== 2) continue;
    need(offset === container.length, "TrailingData");
    const joined = concat(...plaintext);
    let signer = null;
    if (stanza) {
      // metadata_base: the metadata without key 3, extensions kept, canonical.
      const metadataBase = await encode(new Map([...metadata].filter(([k]) => k !== 3)));
      const message = legacy
        ? transcriptLegacy({ objectId, stanzas, metadataBase, plaintext: joined })
        : transcript10({ preamble12: preamble.subarray(0, 12), objectId, stanzas, headerExtensions: header.extensions, metadataBase, plaintext: joined });
      const payload = bindContext(legacy ? CONTEXT_LEGACY : CONTEXT_1_0, message);
      need(verifyHybrid(stanza[1], stanza[2], payload), "InvalidSignature", "signature did not verify");
      signer = stanza[1];
    }
    return { plaintext: joined, metadata, signer, minor, flags, headerExtensions: header.extensions, metadataExtensions, stanzas };
  }
  reject("InvalidContainer", "object too large");
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Assembles a container from parts, recomputing everything a recipient can
/// recompute: encrypted metadata, header_len, header MAC and every record. So a
/// mutant built here passes the MAC and AEAD layers and reaches the structural
/// and signature checks behind them.
///
/// - `preamble`: {major=0, minor=1, kind=1, flags=0} or 12 raw bytes (magic..flags).
/// - `protectedBytes`: used verbatim (key 4 must already hold the sealed metadata);
///   otherwise `protectedMap` is canonically encoded, with key 4 replaced by the
///   sealed metadata when `metadataBytes` or `metadataMap` is given.
/// - `cek`, `salt`, `plaintext`: the object; `objectId` defaults to protectedMap key 2.
export async function rebuild({ preamble = {}, protectedMap, protectedBytes, cek, salt = randomBytes(16), plaintext, metadataMap, metadataBytes, objectId }) {
  const preamble12 = Buffer.isBuffer(preamble) || preamble instanceof Uint8Array
    ? Buffer.from(preamble)
    : concat(magic, [preamble.major ?? 0, preamble.minor ?? 1, preamble.kind ?? 1, preamble.flags ?? 0]);
  assert.equal(preamble12.length, 12, "preamble prefix must be 12 bytes");
  objectId ??= protectedMap?.get(2);
  assert.ok(objectId, "objectId required");
  if (!protectedBytes) {
    const map = new Map(protectedMap);
    const metadata = metadataBytes ?? (metadataMap ? await encode(metadataMap) : undefined);
    if (metadata) map.set(4, aeadSeal(derive(cek, objectId, label("metadata")), Buffer.alloc(12), metadataAad(objectId), metadata));
    protectedBytes = await encode(map);
  }
  const headerLength = (await encode([protectedBytes, Buffer.alloc(32)])).length;
  const fullPreamble = concat(preamble12, uint32(headerLength));
  const mac = createHmac("sha256", derive(cek, objectId, label("header-mac"))).update(fullPreamble).update(protectedBytes).digest();
  const key = derive(cek, salt, concat(label("payload"), objectId));
  const records = [];
  const count = Math.max(1, Math.ceil(plaintext.length / 65536));
  for (let counter = 0; counter < count; counter++) {
    const block = plaintext.subarray(counter * 65536, (counter + 1) * 65536);
    const kind = counter === count - 1 ? 2 : 1;
    const chunk = chunkContext(objectId, protectedBytes, counter, kind, block.length);
    records.push(concat([kind], uint32(block.length + TAG_LEN), aeadSeal(key, chunk.nonce, chunk.aad, block)));
  }
  return concat(fullPreamble, await encode([protectedBytes, mac]), salt, ...records);
}

/// Independent writer. With no options it emits exactly what a 1.0 writer
/// must: minor 1, flags 0, one X-Wing stanza, no extensions. The options exist
/// to produce the GREASE and negative containers a 1.0 writer never would.
///
/// options: { major, minor, kind, flags, filename, mediaType,
///   headerExtensions: [[key, value]], metadataExtensions: [[key, value]],
///   stanzasBefore: [stanza], stanzasAfter: [stanza], includeXWing = true,
///   xwingTag = 1 (another tag disguises a genuine wrap as an unknown stanza),
///   sign: { identity, placement: "public" | "confidential", transcript: "1.0" | "legacy" },
///   extraPublicSignatures: [stanza], confidentialSignature: stanza,
///   afterSign: ({ preamble, protectedMap, metadata }) => void  (mutate post-signing),
///   metadataBytes: Buffer (verbatim metadata plaintext) }
export async function encrypt(publicBytes, plaintext, options = {}) {
  const {
    major = 0, minor = 1, kind = 1, flags = 0,
    filename = "node.txt", mediaType = "text/plain",
    headerExtensions = [], metadataExtensions = [],
    stanzasBefore = [], stanzasAfter = [], includeXWing = true, xwingTag = XWING_TAG,
    sign, extraPublicSignatures = [], confidentialSignature, afterSign, metadataBytes,
  } = options;
  const objectId = options.objectId ?? randomBytes(32);
  const cek = options.cek ?? randomBytes(32);
  const salt = options.salt ?? randomBytes(16);
  const stanzas = [...stanzasBefore];
  if (includeXWing) {
    const publicKey = await kem.deserializePublicKey(publicBytes);
    const context = await suite.createSenderContext({ recipientPublicKey: publicKey, info: concat(label("object-key"), objectId, suiteBytes) });
    const wrapped = Buffer.from(await context.seal(cek, concat(objectId, suiteBytes)));
    stanzas.push([xwingTag, Buffer.from(context.enc), wrapped]);
  }
  stanzas.push(...stanzasAfter);

  const metadata = new Map();
  if (filename !== undefined) metadata.set(1, filename);
  if (mediaType !== undefined) metadata.set(2, mediaType);
  for (const [key, value] of metadataExtensions) metadata.set(key, value);
  const publicSignatures = [];
  const preamble = { major, minor, kind, flags };
  if (sign) {
    const metadataBase = await encode(metadata);
    const legacyTranscript = sign.transcript === "legacy";
    const sortedExtensions = [...headerExtensions].sort(([a], [b]) => a - b);
    const message = legacyTranscript
      ? transcriptLegacy({ objectId, stanzas, metadataBase, plaintext })
      : transcript10({ preamble12: concat(magic, [major, minor, kind, flags]), objectId, stanzas, headerExtensions: sortedExtensions, metadataBase, plaintext });
    const signature = [1, sign.identity.verifyingKey, sign.identity.sign(bindContext(legacyTranscript ? CONTEXT_LEGACY : CONTEXT_1_0, message))];
    if (sign.placement === "confidential") metadata.set(3, signature);
    else publicSignatures.push(signature);
  }
  if (confidentialSignature) metadata.set(3, confidentialSignature);
  publicSignatures.push(...extraPublicSignatures);
  const protectedMap = new Map([[1, SUITE], [2, objectId], [3, stanzas], [4, Buffer.alloc(0)], [5, publicSignatures], ...headerExtensions]);
  afterSign?.({ preamble, protectedMap, metadata });
  return rebuild({ preamble, protectedMap, cek, salt, plaintext, objectId, metadataMap: metadata, metadataBytes });
}

// ---------------------------------------------------------------------------
// Key-file structure (§9.3–§9.6), for key and public-key vectors
// ---------------------------------------------------------------------------

const X25519_SMALL_ORDER = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
  "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
].map((value) => Buffer.from(value, "hex"));

/// §9.3 reader steps 1–5, everything decidable before Argon2. Returns null for
/// a structurally acceptable file, else the reason it must be refused.
export function keyFileProblem(bytes) {
  const keyMagic = Buffer.from("HIDE-KEY", "ascii");
  if (!bytes.subarray(0, 8).equals(keyMagic)) return bytes.length === 32 ? null : "neither a 32-byte seed nor a protected key";
  const version = bytes[8];
  if (version !== 1 && version !== 2) return `unsupported version ${version}`;
  if (bytes.length !== (version === 2 ? 95 : 94)) return "length";
  const parallelism = bytes[9];
  const memoryKib = bytes.readUInt32BE(10);
  const iterations = bytes.readUInt32BE(14);
  if (memoryKib < 8192 || memoryKib > 262144) return `memory_kib ${memoryKib}`;
  if (iterations < 1 || iterations > 64) return `iterations ${iterations}`;
  if (parallelism < 1 || parallelism > 4 || memoryKib / 8 < parallelism) return `parallelism ${parallelism}`;
  if (version === 2 && bytes[46] !== 1 && bytes[46] !== 2) return `purpose ${bytes[46]}`;
  return null;
}

/// §9.5 recipient public key or §9.6 signing public key.
export function publicKeyProblem(bytes) {
  if (bytes.length === 1216) {
    const x25519 = bytes.subarray(1184, 1216);
    return X25519_SMALL_ORDER.some((point) => point.equals(x25519)) ? "small-order X25519 component" : null;
  }
  if (bytes.length === VERIFYING_KEY_LEN) return hasSmallOrder(bytes.subarray(0, 32)) ? "small-order Ed25519 component" : null;
  return `length ${bytes.length}`;
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

async function expectRejection(promise, code, what) {
  try {
    await promise;
  } catch (error) {
    if (!(error instanceof Rejection)) throw new Error(`${what}: failed with a non-Rejection: ${error.message}`, { cause: error });
    assert.equal(error.code, code, `${what}: rejected as ${error.message}, expected ${code}`);
    return;
  }
  assert.fail(`${what}: accepted; expected ${code}`);
}

async function selfTests(publicKey, secret) {
  const lines = [];
  const pt = Buffer.from("GREASE must open in every 1.0 reader\n");
  const grease = {
    headerExtensions: [[0xfafa, Buffer.from("header grease")]],
    metadataExtensions: [[0x4a4a, Buffer.from("metadata grease")]],
    stanzasBefore: [[0x7a7a, Buffer.from("unknown stanza field")]],
  };
  const identity = newSigningIdentity();
  const opens = async (options, what) => {
    const result = await decrypt(await encrypt(publicKey, pt, options), secret);
    assert.deepEqual(result.plaintext, pt, what);
    lines.push(`Node self-test: ${what} opens`);
    return result;
  };
  const refuses = async (options, code, what) => {
    await expectRejection(decrypt(await encrypt(publicKey, pt, options), secret), code, what);
    lines.push(`Node self-test: ${what} -> ${code}`);
  };

  const plain = await opens({}, "plain 1.0 (minor 1, flags 0)");
  assert.equal(plain.signer, null);
  const g = await opens(grease, "unsigned GREASE (header ext 0xFAFA, metadata ext 0x4A4A, unknown stanza 0x7A7A)");
  assert.equal(g.headerExtensions.length, 1);
  assert.equal(g.metadataExtensions.length, 1);
  assert.equal(g.stanzas[0][0], 0x7a7a);
  const gs = await opens({ ...grease, flags: FLAG_SIGNED, sign: { identity } }, "signed GREASE, public placement (flags 0x01)");
  assert.deepEqual(gs.signer, identity.verifyingKey);
  const gc = await opens({ ...grease, flags: FLAG_SIGNED, sign: { identity, placement: "confidential" } }, "signed GREASE, confidential placement");
  assert.deepEqual(gc.signer, identity.verifyingKey);
  await opens({ minor: 7 }, "minor 7 (non-breaking revision)");
  await opens({ minor: 255, flags: FLAG_SIGNED, sign: { identity } }, "minor 255 signed");
  await opens({ stanzasAfter: [[9, Buffer.alloc(65536)], [65535]] }, "unknown stanzas after X-Wing, max field / tag-only");
  await opens({ headerExtensions: Array.from({ length: 16 }, (_, i) => [64 + i, Buffer.alloc(i)]) }, "16 header extensions");
  await opens({ filename: "hello.txt" }, "filename hello.txt");
  await opens({ filename: ".profile" }, "filename .profile");
  await opens({ minor: 2, sign: { identity, transcript: "legacy" } }, "Node-written legacy minor 2 (HIDE/0.5 transcript)");

  await refuses({ minor: 0 }, "UnsupportedVersion", "minor 0");
  await refuses({ major: 1 }, "UnsupportedVersion", "major 1");
  await refuses({ kind: 2 }, "UnsupportedFeature", "kind 2");
  await refuses({ flags: 0x02 }, "UnsupportedFeature", "flags 0x02");
  await refuses({ flags: 0x80 | FLAG_SIGNED, sign: { identity } }, "UnsupportedFeature", "flags 0x81");
  await refuses({ minor: 2, flags: FLAG_SIGNED, sign: { identity } }, "UnsupportedFeature", "minor 2 with flag 0x01");
  await refuses({ headerExtensions: [[6, Buffer.alloc(1)]] }, "UnsupportedFeature", "critical header key 6");
  await refuses({ headerExtensions: [[63, Buffer.alloc(1)]] }, "UnsupportedFeature", "critical header key 63");
  await refuses({ headerExtensions: [[65536, Buffer.alloc(1)]] }, "MalformedHeader", "header key 65536");
  await refuses({ headerExtensions: [[64, Buffer.alloc(65537)]] }, "MalformedHeader", "header extension of 65537 bytes");
  await refuses({ headerExtensions: [[64, "text"]] }, "MalformedHeader", "header extension not a bstr");
  await refuses({ headerExtensions: Array.from({ length: 17 }, (_, i) => [64 + i, Buffer.alloc(0)]) }, "MalformedHeader", "17 header extensions");
  await refuses({ metadataExtensions: [[4, Buffer.alloc(1)]] }, "UnsupportedFeature", "reserved metadata key 4");
  await refuses({ metadataExtensions: [[7, Buffer.alloc(1)]] }, "UnsupportedFeature", "critical metadata key 7");
  await refuses({ metadataExtensions: [[70000, Buffer.alloc(1)]] }, "InvalidMetadata", "metadata key 70000");
  await refuses({ metadataExtensions: [[64, 5]] }, "InvalidMetadata", "metadata extension not a bstr");
  await refuses({ metadataExtensions: Array.from({ length: 17 }, (_, i) => [64 + i, Buffer.alloc(0)]) }, "InvalidMetadata", "17 metadata extensions");
  await refuses({ includeXWing: false, stanzasBefore: [[0x7a7a, Buffer.alloc(4)]] }, "NoMatchingRecipient", "only unknown stanzas");
  // A genuine wrap to this recipient under an unknown tag must be skipped,
  // not trial-decapsulated: tags, not shapes, decide what a stanza is.
  await refuses({ xwingTag: 0x7a7a }, "NoMatchingRecipient", "valid X-Wing wrap under unknown tag 0x7A7A");
  await refuses({ stanzasBefore: [[0, Buffer.alloc(4)]] }, "MalformedHeader", "stanza tag 0");
  await refuses({ stanzasBefore: [[65536]] }, "MalformedHeader", "stanza tag 65536");
  await refuses({ stanzasBefore: [[9, "text"]] }, "MalformedHeader", "stanza field not a bstr");
  await refuses({ stanzasBefore: [[9, Buffer.alloc(65537)]] }, "MalformedHeader", "stanza field of 65537 bytes");
  await refuses({ stanzasBefore: [[9, ...Array.from({ length: 8 }, () => Buffer.alloc(0))]] }, "MalformedHeader", "stanza with 9 items");
  await refuses({ stanzasBefore: [[1, Buffer.alloc(1120)]] }, "MalformedHeader", "X-Wing stanza with 2 items");
  await refuses({ stanzasAfter: Array.from({ length: 64 }, () => [9]) }, "MalformedHeader", "65 stanzas (unknown ones count)");
  for (const name of ["..", ".", "a.", "a ", "", "a/b", "a\\b", "a:b", "a\u0001b", "a\u0085b", "CON", "con.txt", "Com1.log", "LPT9", "x".repeat(256)]) {
    await refuses({ filename: name }, "InvalidMetadata", `filename ${JSON.stringify(name)}`);
  }
  await refuses({ mediaType: "" }, "InvalidMetadata", "empty media_type");
  await refuses({ mediaType: "text/plain\n" }, "InvalidMetadata", "media_type with control char");
  await refuses({ mediaType: "text/\u00e9" }, "InvalidMetadata", "media_type non-ASCII");
  // a1 01 63 "a.b" with the map count written as b8 01: well-formed, not canonical.
  await refuses({ metadataBytes: Buffer.from("b8010163612e62", "hex") }, "NonCanonical", "non-canonical metadata");

  // Signature obligations.
  const signedOnce = { flags: FLAG_SIGNED, sign: { identity } };
  await refuses({ flags: FLAG_SIGNED }, "InvalidSignature", "stripped (flags 0x01, no signature)");
  await refuses({ minor: 2 }, "InvalidSignature", "stripped legacy (minor 2, no signature)");
  await refuses({ sign: { identity } }, "InvalidSignature", "unexpected (signature, flags 0)");
  await refuses({ minor: 3, sign: { identity } }, "InvalidSignature", "unexpected (signature, minor 3 flags 0)");
  const spare = [1, identity.verifyingKey, Buffer.alloc(SIGNATURE_LEN)];
  await refuses({ ...signedOnce, extraPublicSignatures: [spare] }, "MalformedHeader", "two public signatures");
  await refuses({ ...signedOnce, confidentialSignature: spare }, "InvalidSignature", "signature in both places");
  await refuses({ flags: FLAG_SIGNED, extraPublicSignatures: [[2, identity.verifyingKey, Buffer.alloc(SIGNATURE_LEN)]] }, "UnsupportedFeature", "signature stanza tag 2");
  await refuses({ flags: FLAG_SIGNED, extraPublicSignatures: [[1, identity.verifyingKey]] }, "UnsupportedFeature", "signature stanza with 2 items");
  await refuses({ flags: FLAG_SIGNED, confidentialSignature: [1, Buffer.alloc(1983), Buffer.alloc(SIGNATURE_LEN)] }, "UnsupportedFeature", "confidential signature, short key");
  await refuses({ ...signedOnce, sign: { identity, transcript: "legacy" } }, "InvalidSignature", "flags 0x01 signed with the legacy transcript");
  await refuses({ minor: 2, sign: { identity } }, "InvalidSignature", "minor 2 signed with the 1.0 transcript");

  // Legacy minor 2 must not carry what its transcript does not bind.
  const legacySigned = { minor: 2, sign: { identity, transcript: "legacy" } };
  await refuses({ ...legacySigned, headerExtensions: [[0xfafa, Buffer.alloc(1)]] }, "MalformedHeader", "minor 2 with header extension");
  await refuses({ ...legacySigned, metadataExtensions: [[0x4a4a, Buffer.alloc(1)]] }, "MalformedHeader", "minor 2 with metadata extension");
  await refuses({ ...legacySigned, stanzasBefore: [[0x7a7a]] }, "MalformedHeader", "minor 2 with unknown stanza");

  // The 1.0 transcript binds everything a recipient could rewrite and re-MAC.
  const tampered = async (mutate, what) => refuses({ ...grease, ...signedOnce, afterSign: mutate }, "InvalidSignature", `signed, then ${what}`);
  await tampered(({ protectedMap }) => protectedMap.set(0xfafa, Buffer.from("changed")), "header extension value changed");
  await tampered(({ protectedMap }) => protectedMap.set(0xfafb, Buffer.from("added")), "header extension added");
  await tampered(({ protectedMap }) => protectedMap.delete(0xfafa), "header extension removed");
  await tampered(({ metadata }) => metadata.set(0x4a4a, Buffer.from("changed")), "metadata extension changed");
  await tampered(({ metadata }) => metadata.set(1, "other.txt"), "filename changed");
  await tampered(({ protectedMap }) => protectedMap.get(3)[0].push(Buffer.alloc(0)), "unknown stanza field appended");
  await tampered(({ protectedMap }) => { protectedMap.get(3)[0][0] = 0x7a7b; }, "unknown stanza tag changed");
  await tampered(({ protectedMap }) => protectedMap.get(3).reverse(), "stanza order swapped");
  await tampered(({ protectedMap }) => protectedMap.get(3).shift(), "unknown stanza removed");
  await tampered(({ preamble }) => { preamble.minor = 3; }, "minor 1 -> 3");

  // Ed25519 strictness. With A = R = the identity point and S = 0 the
  // cofactorless equation [S]B = R + [k]A holds for EVERY message, and
  // node:crypto accepts it; only the small-order blocklist refuses it. The
  // ML-DSA half is genuine, so the Ed25519 check is the only thing deciding.
  const pq = ml_dsa65.keygen(randomBytes(32));
  const identityPoint = Buffer.from(SMALL_ORDER_ED25519[1]);
  const weak = {
    verifyingKey: concat(identityPoint, pq.publicKey),
    sign: (payload) => concat(identityPoint, Buffer.alloc(32), ml_dsa65.sign(payload, pq.secretKey)),
  };
  const probe = createPublicKey({ key: concat(ED25519_SPKI, identityPoint), format: "der", type: "spki" });
  assert.ok(nodeVerify(null, Buffer.from("any"), probe, concat(identityPoint, Buffer.alloc(32))), "premise: node:crypto accepts the small-order forgery");
  await refuses({ flags: FLAG_SIGNED, sign: { identity: weak } }, "InvalidSignature", "small-order Ed25519 A and R (node:crypto alone accepts)");
  const highS = {
    verifyingKey: identity.verifyingKey,
    sign: (payload) => {
      const real = identity.sign(payload);
      const s = littleEndian(real.subarray(32, 64)) + ED25519_L;
      const bytes = Buffer.alloc(32);
      for (let i = 0, v = s; i < 32; i++, v >>= 8n) bytes[i] = Number(v & 0xffn);
      return concat(real.subarray(0, 32), bytes, real.subarray(64));
    },
  };
  await refuses({ flags: FLAG_SIGNED, sign: { identity: highS } }, "InvalidSignature", "Ed25519 S + L (non-canonical S)");
  // The explicit S < L check is defence in depth: node:crypto also refuses it.
  // Pinned so that, should that ever change, the explicit check is what holds.
  {
    const payload = Buffer.from("premise");
    const edKey = createPublicKey({ key: concat(ED25519_SPKI, identity.verifyingKey.subarray(0, 32)), format: "der", type: "spki" });
    assert.equal(nodeVerify(null, payload, edKey, highS.sign(payload).subarray(0, 64)), false, "premise: node:crypto refuses S + L");
  }
  const halfBroken = { verifyingKey: identity.verifyingKey, sign: (payload) => { const s = identity.sign(payload); s[s.length - 1] ^= 1; return s; } };
  await refuses({ flags: FLAG_SIGNED, sign: { identity: halfBroken } }, "InvalidSignature", "ML-DSA half flipped");
  return lines;
}

async function readVector(vectors, path) {
  return Buffer.from(await readFile(new URL(path, vectors)));
}

async function checkFrozen(vectors, secret, identitySecret) {
  const lines = [];
  const openable = [["hello", secret], ["empty", secret]];
  if (identitySecret && existsSync(new URL("identity.hide", vectors))) openable.push(["identity", identitySecret]);
  for (const [name, key] of openable) {
    const ciphertext = await readVector(vectors, `${name}.hide`);
    const expected = await readVector(vectors, `${name}.txt`);
    const result = await decrypt(ciphertext, key);
    assert.deepEqual(result.plaintext, expected);
    assert.equal(result.metadata.get(1), `${name}.txt`);
    await assert.rejects(decrypt(ciphertext.subarray(0, -1), key));
    await assert.rejects(decrypt(concat(ciphertext, [0]), key));
    const corrupt = Buffer.from(ciphertext);
    corrupt[corrupt.length - 1] ^= 1;
    await assert.rejects(decrypt(corrupt, key));
    lines.push(`Rust -> independent Node: ${name}; truncation/tamper/trailing rejected`);
  }

  // Signed containers, verified with an independent Ed25519 (node:crypto plus
  // the strict blocklist) and an independent ML-DSA-65 (@noble/post-quantum).
  const signerKey = await readVector(vectors, "signed.test-public");
  for (const name of ["signed-public", "signed-confidential"]) {
    const ciphertext = await readVector(vectors, `${name}.hide`);
    const expected = await readVector(vectors, `${name}.txt`);
    const result = await decrypt(ciphertext, secret);
    assert.deepEqual(result.plaintext, expected);
    assert.ok(result.signer, `${name} reported no signer`);
    assert.deepEqual(Buffer.from(result.signer), signerKey, `${name} signer mismatch`);
    // The public placement must expose the signer; the confidential one must not.
    assert.equal(ciphertext.includes(signerKey), name === "signed-public", `${name} signer visibility is wrong`);
    const corrupt = Buffer.from(ciphertext);
    corrupt[corrupt.length - 1] ^= 1;
    await assert.rejects(decrypt(corrupt, secret));
    for (const minor of [1, 3]) {
      const downgraded = Buffer.from(ciphertext);
      downgraded[9] = minor;
      await assert.rejects(decrypt(downgraded, secret));
    }
    lines.push(`Rust -> independent Node signature (minor ${result.minor}): ${name}; tamper/downgrade rejected`);
  }
  return lines;
}

async function checkRejectionIndex(vectors, secret) {
  // Fallback until manifest.json exists: the rejection index. An independent
  // decoder must refuse each one without having read the Rust code.
  const rejections = new URL("rejections/", vectors);
  const index = (await readFile(new URL("rejections.txt", rejections), "utf8"))
    .split(/\r?\n/)
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => line.split("\t"));
  for (const [name, reason] of index) {
    if (name.endsWith(".test-secret")) {
      assert.ok(keyFileProblem(await readFile(new URL(name, rejections))), `${name} must be refused: ${reason}`);
    } else if (name.endsWith(".test-public")) {
      assert.ok(publicKeyProblem(await readFile(new URL(name, rejections))), `${name} must be refused: ${reason}`);
    } else {
      await assert.rejects(decrypt(await readFile(new URL(`${name}.hide`, rejections)), secret), undefined, `${name} must be refused: ${reason}`);
    }
  }
  return [`independent Node refuses all ${index.length} rejection vectors (rejections.txt)`];
}

export async function checkManifest(vectors, manifest, secret, identitySecret) {
  assert.equal(manifest.format, "hide-vectors/1", "manifest format");
  assert.ok(Array.isArray(manifest.vectors) && manifest.vectors.length > 0, "manifest lists no vectors");
  const counts = {};
  for (const entry of manifest.vectors) {
    const { path, kind, expect, reason = "" } = entry;
    const what = `${path} (${kind}, ${expect}${reason ? `: ${reason}` : ""})`;
    assert.ok(expect === "open" || expect === "reject", `${what}: expect`);
    const bytes = await readVector(vectors, path);
    assert.equal(hash(bytes).toString("hex"), String(entry.sha256).toLowerCase(), `${what}: sha256 mismatch`);
    if (kind === "container") {
      // identity.hide is sealed to the key derived from identity.test-seed
      // (§9.1); every other container vector to the legacy recipient.test-secret.
      const key = basename(path) === "identity.hide" ? identitySecret : secret;
      assert.ok(key, `${what}: no key available`);
      if (expect === "open") {
        const result = await decrypt(bytes, key);
        const sibling = new URL(path.replace(/\.hide$/, ".txt"), vectors);
        if (existsSync(sibling)) assert.deepEqual(result.plaintext, await readFile(sibling), `${what}: plaintext`);
      } else {
        await assert.rejects(decrypt(bytes, key), undefined, `${what} must be refused`);
      }
    } else if (kind === "key") {
      assert.equal(keyFileProblem(bytes) === null, expect === "open", `${what}: key-file structure (${keyFileProblem(bytes)})`);
    } else if (kind === "public-key") {
      assert.equal(publicKeyProblem(bytes) === null, expect === "open", `${what}: public-key structure (${publicKeyProblem(bytes)})`);
    } else if (kind === "detached-signature") {
      // Implementation-defined format (spec §14): the hash is the only obligation.
    } else {
      // Subsystem vectors are verified semantically by verifySubsystems.
      assert.equal(kind, "subsystem", `${what}: unknown kind`);
    }
    const bucket = `${kind}/${expect}`;
    counts[bucket] = (counts[bucket] ?? 0) + 1;
  }
  const summary = Object.entries(counts).map(([bucket, n]) => `${bucket} ${n}`).join(", ");
  return [`manifest.json: ${manifest.vectors.length} vectors, sha256 verified; ${summary}`];
}

async function main() {
  const root = new URL("../../", import.meta.url);
  const vectors = new URL("../vectors/", import.meta.url);
  const out = (lines) => lines.forEach((line) => console.log(`PASS ${line}`));

  // Known-answer probes for the deterministic encoder: array framing, and map
  // keys ordered by encoding (1 < 64250) whatever the insertion order.
  assert.deepEqual(await encode([Buffer.from([1, 2]), Buffer.alloc(3)]), Buffer.from("8242010243000000", "hex"));
  assert.deepEqual(await encode(new Map([[0xfafa, Buffer.from("x")], [1, 1]])), Buffer.from("a2010119fafa4178", "hex"));

  const secret = await readVector(vectors, "recipient.test-secret");
  const publicKey = await readVector(vectors, "recipient.test-public");
  const seedUrl = new URL("identity.test-seed", vectors);
  const identitySecret = existsSync(seedUrl) ? recipientSeedFromMaster(await readFile(seedUrl)) : null;

  out(await checkFrozen(vectors, secret, identitySecret));

  const scratch = new URL(".copilot-tmp/", root);
  await mkdir(scratch, { recursive: true });
  const plaintext = Buffer.alloc(131079, 0x5a);
  const container = await encrypt(publicKey, plaintext);
  assert.deepEqual(container.subarray(8, 12), Buffer.from([0, 1, 1, 0]), "1.0 writer must emit minor 1 flags 0");
  assert.deepEqual((await decrypt(container, secret)).plaintext, plaintext);
  await writeFile(new URL("node-interop.hide", scratch), container);
  await writeFile(new URL("node-interop.txt", scratch), plaintext);
  out(["independent Node encoder; cross-check artifact: .copilot-tmp/node-interop.hide"]);

  out(await selfTests(publicKey, secret));

  const manifestUrl = new URL("manifest.json", vectors);
  if (existsSync(manifestUrl)) {
    out(await checkManifest(vectors, JSON.parse(await readFile(manifestUrl, "utf8")), secret, identitySecret));
  } else {
    out(await checkRejectionIndex(vectors, secret));
  }

  out(await verifySubsystems(vectors));
  console.log("verify.mjs: all checks passed");
}

if (process.argv[1] && resolve(fileURLToPath(import.meta.url)) === resolve(process.argv[1])) {
  await main();
}
