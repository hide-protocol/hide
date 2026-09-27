// Independent verifier for the HIDE subsystem wire structures (spec §8–§10):
// identity logs, epoch chains and transparency proofs. Nothing here calls the
// Rust crates; every byte layout is re-derived from first principles and
// checked against the frozen vectors in conformance/vectors/subsystems/.

import assert from "node:assert/strict";
import { createHash, createPublicKey, verify as nodeVerify } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import cbor from "cbor";

const concat = (...parts) => Buffer.concat(parts.map((part) => Buffer.from(part)));
const ascii = (value) => Buffer.from(value, "ascii");
const sha256 = (...parts) => {
  const hasher = createHash("sha256");
  for (const part of parts) hasher.update(part);
  return hasher.digest();
};
const u64be = (value) => {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(value));
  return out;
};
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const flipLast = (bytes) => {
  const copy = Buffer.from(bytes);
  copy[copy.length - 1] ^= 1;
  return copy;
};

/// A refusal with a machine-checkable reason, so a negative vector can be shown
/// to fail for the intended cause rather than for any cause.
class Rejection extends Error {
  constructor(code, at) {
    super(at === undefined ? code : `${code}(${at})`);
    this.code = code;
    this.at = at;
  }
}

function expectRejection(fn, code, at) {
  try {
    fn();
  } catch (error) {
    if (!(error instanceof Rejection)) throw error;
    assert.equal(error.code, code, `rejected as ${error.message}, expected ${code}`);
    if (at !== undefined) assert.equal(error.at, at, `rejected as ${error.message}, expected ${code}(${at})`);
    return error.message;
  }
  assert.fail(`accepted; expected rejection ${code}`);
}

// ---------------------------------------------------------------------------
// HIDE-Sign: hybrid Ed25519 (strict) + ML-DSA-65
// ---------------------------------------------------------------------------

const ED25519_PUBLIC_LEN = 32;
const ED25519_SIGNATURE_LEN = 64;
const ML_DSA_PUBLIC_LEN = 1952;
const ML_DSA_SIGNATURE_LEN = 3309;
const VERIFYING_KEY_LEN = ED25519_PUBLIC_LEN + ML_DSA_PUBLIC_LEN; // 1984
const SIGNATURE_LEN = ED25519_SIGNATURE_LEN + ML_DSA_SIGNATURE_LEN; // 3373
const ED25519_SPKI = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_L = (1n << 252n) + 27742317777372353535851937790883648493n;

// libsodium's ge25519_has_small_order blocklist: every encoding (canonical or
// not) of a point of order 1, 2, 4 or 8. Compared on bytes 0..30 plus byte 31
// with the sign bit masked, which is what makes the sign-flipped forms match.
const SMALL_ORDER = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
].map((value) => Buffer.from(value, "hex"));

function hasSmallOrder(point) {
  return SMALL_ORDER.some((blocked) => {
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

/// Ed25519 with the extra refusals ed25519-dalek's verify_strict applies.
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

/// hide-sign `bind`: u64be(len(context)) || context || message.
function bind(context, message) {
  return concat(u64be(context.length), context, message);
}

export const hideSign = {
  checkEd25519: true,
  checkMlDsa: true,
};

/// hide-sign `VerifyingIdentity::verify`. Both halves are evaluated before the
/// decision; neither alone is accepted.
function verifyHybrid(verifyingKey, context, message, signature) {
  assert.equal(verifyingKey.length, VERIFYING_KEY_LEN, "verifying key length");
  if (signature.length !== SIGNATURE_LEN) return false;
  const payload = bind(context, message);
  const classical = !hideSign.checkEd25519 ||
    ed25519Strict(verifyingKey.subarray(0, 32), signature.subarray(0, 64), payload);
  let quantum = false;
  try {
    quantum = !hideSign.checkMlDsa ||
      ml_dsa65.verify(signature.subarray(64), payload, verifyingKey.subarray(32));
  } catch {
    quantum = false;
  }
  return classical && quantum;
}

// ---------------------------------------------------------------------------
// Strict CBOR subset: unsigned ints, byte strings, text strings, arrays.
// Definite lengths and shortest-form arguments only; anything else is refused.
// ---------------------------------------------------------------------------

class StrictReader {
  constructor(bytes) {
    this.bytes = bytes;
    this.position = 0;
  }

  head(expectedMajor) {
    if (this.position >= this.bytes.length) throw new Rejection("Malformed");
    const initial = this.bytes[this.position++];
    const major = initial >> 5;
    const info = initial & 0x1f;
    if (major !== expectedMajor) throw new Rejection("Malformed");
    if (info < 24) return BigInt(info);
    const widths = { 24: 1, 25: 2, 26: 4, 27: 8 };
    const width = widths[info];
    if (width === undefined) throw new Rejection("Malformed"); // indefinite or reserved
    if (this.position + width > this.bytes.length) throw new Rejection("Malformed");
    let value = 0n;
    for (let i = 0; i < width; i++) value = (value << 8n) | BigInt(this.bytes[this.position++]);
    const minimum = { 1: 24n, 2: 0x100n, 4: 0x10000n, 8: 0x100000000n }[width];
    if (value < minimum) throw new Rejection("Malformed"); // not shortest form
    return value;
  }

  uint() {
    return this.head(0);
  }

  array() {
    return this.head(4);
  }

  #string(major) {
    const length = this.head(major);
    // Bound before slicing: the length is untrusted.
    if (length > BigInt(this.bytes.length - this.position)) throw new Rejection("Malformed");
    const start = this.position;
    this.position += Number(length);
    return this.bytes.subarray(start, this.position);
  }

  bytestring() {
    return this.#string(2);
  }

  text() {
    const raw = this.#string(3);
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(raw);
    } catch {
      throw new Rejection("Malformed");
    }
  }

  finish() {
    if (this.position !== this.bytes.length) throw new Rejection("Malformed");
  }
}

function cborHead(major, value) {
  const n = BigInt(value);
  const m = major << 5;
  if (n < 24n) return Buffer.from([m | Number(n)]);
  if (n < 0x100n) return Buffer.from([m | 24, Number(n)]);
  if (n < 0x10000n) {
    const b = Buffer.alloc(3);
    b[0] = m | 25;
    b.writeUInt16BE(Number(n), 1);
    return b;
  }
  if (n < 0x100000000n) {
    const b = Buffer.alloc(5);
    b[0] = m | 26;
    b.writeUInt32BE(Number(n), 1);
    return b;
  }
  const b = Buffer.alloc(9);
  b[0] = m | 27;
  b.writeBigUInt64BE(n, 1);
  return b;
}
const cborUint = (value) => cborHead(0, value);
const cborBytes = (bytes) => concat(cborHead(2, bytes.length), bytes);
const cborText = (text) => {
  const raw = Buffer.from(text, "utf8");
  return concat(cborHead(3, raw.length), raw);
};
const cborArray = (count) => cborHead(4, count);

// ---------------------------------------------------------------------------
// §8 Identity logs
// ---------------------------------------------------------------------------

const ENTRY_CONTEXT = ascii("HIDE/0.6 identity entry");
const LINK_LABEL = ascii("HIDE/0.6 identity link");
const DEVICE_ID_LABEL = ascii("HIDE/0.6 device id");
const MAX_ENTRIES = 100_000n;
const MAX_LABEL_BYTES = 256;
const ENTRY_FIELDS = 7n;
const LEGACY_ENTRY_HEADER = 6n;
const TAGS = { 1: "Create", 2: "Enrol", 3: "Revoke", 4: "Recover" };
const ZERO32 = Buffer.alloc(32);

const deviceId = (verifyingKey) => sha256(DEVICE_ID_LABEL, verifyingKey);

function encodeIdentity(entries, header) {
  const parts = [cborArray(entries.length)];
  for (const entry of entries) {
    parts.push(
      cborArray(header),
      cborUint(entry.sequence),
      cborUint(entry.tag),
      cborBytes(entry.payload),
      cborText(entry.tag === 3 ? "" : entry.label),
      cborBytes(entry.signer),
      cborBytes(entry.link),
      cborBytes(entry.signature),
    );
  }
  return concat(...parts);
}

/// Decodes a log in either framing. Returns entries plus the framing header seen.
export function decodeIdentity(bytes) {
  const reader = new StrictReader(bytes);
  const count = reader.array();
  if (count > MAX_ENTRIES) throw new Rejection("TooManyEntries");
  const entries = [];
  let framing = null;
  for (let i = 0n; i < count; i++) {
    const header = reader.array();
    // Both framings carry seven items; only the header's claim differs.
    if (header !== ENTRY_FIELDS && header !== LEGACY_ENTRY_HEADER) throw new Rejection("Malformed");
    if (framing !== null && framing !== header) throw new Rejection("Malformed");
    framing = header;
    const sequence = reader.uint();
    if (sequence > 0xffffffffffffffffn) throw new Rejection("Malformed");
    const tagValue = reader.uint();
    if (tagValue > 255n) throw new Rejection("Malformed");
    const tag = Number(tagValue);
    const payload = reader.bytestring();
    const label = reader.text();
    if (Buffer.byteLength(label, "utf8") > MAX_LABEL_BYTES) throw new Rejection("LabelTooLong");
    if (!TAGS[tag]) throw new Rejection("Malformed");
    if (tag === 3 && payload.length !== 32) throw new Rejection("Malformed");
    const signer = reader.bytestring();
    const link = reader.bytestring();
    const signature = reader.bytestring();
    if (signer.length !== 32 || link.length !== 32) throw new Rejection("Malformed");
    if (signature.length !== SIGNATURE_LEN) throw new Rejection("Malformed");
    entries.push({ sequence, tag, payload, label, signer, link, signature });
  }
  reader.finish();
  // One history, one encoding. Also refuses a non-empty label on a Revoke.
  if (!encodeIdentity(entries, framing ?? ENTRY_FIELDS).equals(bytes)) throw new Rejection("Malformed");
  return { entries, framing: framing ?? ENTRY_FIELDS };
}

/// spec §8 `signed`.
export function identitySignedBytes(previous, entry) {
  const field = (bytes) => concat(u64be(bytes.length), bytes);
  const fields = entry.tag === 3
    ? [field(entry.payload)]
    : [field(entry.payload), field(Buffer.from(entry.label, "utf8"))];
  return concat(previous, u64be(entry.sequence), Buffer.from([entry.tag]), entry.signer, ...fields);
}

const identityLink = (signed, signature) =>
  sha256(LINK_LABEL, u64be(signed.length), signed, u64be(signature.length), signature);

export const identityChecks = { link: true, signature: true, authority: true };

/// Replays a log exactly as `hide_identity::replay`: authority is decided at
/// each entry's position, never against the final state.
export function replayIdentity(entries, recoveryKey) {
  if (entries.length === 0) throw new Rejection("Empty");
  if (BigInt(entries.length) > MAX_ENTRIES) throw new Rejection("TooManyEntries");
  if (entries[0].tag !== 1) throw new Rejection("BadRoot");
  const devices = new Map(); // hex(id) -> { key, label, enrolledAt }
  const revoked = new Map(); // hex(id) -> sequence
  const recoveryId = hex(deviceId(recoveryKey));
  let previous = ZERO32;

  entries.forEach((entry, index) => {
    const seq = BigInt(index);
    if (entry.sequence !== seq) throw new Rejection("OutOfOrder", index);
    if (entry.tag !== 3 && Buffer.byteLength(entry.label, "utf8") > MAX_LABEL_BYTES) {
      throw new Rejection("LabelTooLong");
    }
    const signed = identitySignedBytes(previous, entry);
    if (identityChecks.link && !identityLink(signed, entry.signature).equals(entry.link)) {
      throw new Rejection("BrokenLink", index);
    }
    if (entry.signature.length !== SIGNATURE_LEN) throw new Rejection("BadSignature", index);

    const parseKey = () => {
      if (entry.payload.length !== VERIFYING_KEY_LEN) throw new Rejection("Malformed");
      return entry.payload;
    };
    let author;
    const signerHex = hex(entry.signer);
    switch (entry.tag) {
      case 1: {
        if (index !== 0) throw new Rejection("BadRoot");
        const key = parseKey();
        if (identityChecks.authority && hex(deviceId(key)) !== signerHex) throw new Rejection("Unauthorised", index);
        author = key;
        break;
      }
      case 4:
        // Only the recovery key, which is not a device.
        if (identityChecks.authority && recoveryId !== signerHex) throw new Rejection("Unauthorised", index);
        author = recoveryKey;
        break;
      default: {
        const device = devices.get(signerHex);
        if (!device) {
          if (identityChecks.authority) throw new Rejection("Unauthorised", index);
          author = recoveryKey;
        } else {
          author = device.key;
        }
      }
    }
    if (identityChecks.signature && !verifyHybrid(author, ENTRY_CONTEXT, signed, entry.signature)) {
      throw new Rejection("BadSignature", index);
    }

    switch (entry.tag) {
      case 1: {
        const key = parseKey();
        devices.set(hex(deviceId(key)), { key, label: entry.label, enrolledAt: index });
        break;
      }
      case 2: {
        const key = parseKey();
        const id = hex(deviceId(key));
        if (devices.has(id)) throw new Rejection("AlreadyEnrolled", index);
        revoked.delete(id);
        devices.set(id, { key, label: entry.label, enrolledAt: index });
        break;
      }
      case 3: {
        const id = hex(entry.payload);
        if (!devices.has(id)) throw new Rejection("NotEnrolled", index);
        if (devices.size === 1) throw new Rejection("WouldOrphan", index);
        devices.delete(id);
        revoked.set(id, index);
        break;
      }
      case 4: {
        const key = parseKey();
        const id = hex(deviceId(key));
        for (const old of devices.keys()) revoked.set(old, index);
        devices.clear();
        revoked.delete(id);
        devices.set(id, { key, label: entry.label, enrolledAt: index });
        break;
      }
    }
    previous = entry.link;
  });
  return { devices, revoked, head: previous };
}

/// Whether a generic CBOR library sees exactly one top-level item that is an
/// array of seven-item arrays. The legacy framing cannot pass this.
function genericReaderSeesSevenItemEntries(bytes) {
  try {
    const items = cbor.decodeAllSync(bytes);
    return items.length === 1 && Array.isArray(items[0]) &&
      items[0].every((entry) => Array.isArray(entry) && entry.length === 7);
  } catch {
    return false;
  }
}

async function verifyIdentity(read) {
  const lines = [];
  const legacy = await read("identity-log-legacy.bin");
  const current = await read("identity-log.bin");
  const tampered = await read("identity-tampered.bin");
  const tamperedLegacy = await read("identity-tampered-legacy.bin");
  const head = await read("identity-head.bin");
  const recovery = await read("identity-recovery.bin");
  const phone = await read("identity-device-phone.bin");
  const laptop = await read("identity-device-laptop.bin");
  for (const key of [recovery, phone, laptop]) assert.equal(key.length, VERIFYING_KEY_LEN);
  assert.equal(head.length, 32);

  assert.deepEqual([...current.subarray(0, 8)], [0x84, 0x87, 0x00, 0x01, 0x59, 0x07, 0xc0, 0x60]);
  assert.deepEqual([...legacy.subarray(0, 6)], [0x84, 0x86, 0x00, 0x01, 0x59, 0x07]);
  assert.ok(genericReaderSeesSevenItemEntries(current), "a generic CBOR reader misreads identity-log.bin");
  assert.ok(!genericReaderSeesSevenItemEntries(legacy), "a generic CBOR reader parsed the legacy framing");
  lines.push("identity: identity-log.bin is array(7)-framed and parses with a generic CBOR library; the legacy file does not");

  const phoneId = hex(deviceId(phone));
  const laptopId = hex(deviceId(laptop));
  for (const [name, bytes, framing] of [["identity-log.bin", current, ENTRY_FIELDS], ["identity-log-legacy.bin", legacy, LEGACY_ENTRY_HEADER]]) {
    const decoded = decodeIdentity(bytes);
    assert.equal(decoded.framing, framing);
    const { entries } = decoded;
    assert.deepEqual(entries.map((e) => TAGS[e.tag]), ["Create", "Enrol", "Enrol", "Revoke"]);
    const { devices, revoked, head: computed } = replayIdentity(entries, recovery);
    assert.equal(devices.size, 2);
    assert.ok(devices.has(phoneId), "phone not trusted");
    assert.ok(!devices.has(laptopId), "laptop still trusted");
    assert.equal(revoked.get(laptopId), 3);
    assert.ok(computed.equals(head), `${name} head ${hex(computed)} != identity-head.bin`);
    lines.push(`identity: ${name} replays 4 entries (create, enrol phone, enrol laptop, revoke laptop@3) to head ${hex(head).slice(0, 16)}…`);
  }

  const fromLegacy = decodeIdentity(legacy).entries;
  assert.ok(encodeIdentity(fromLegacy, ENTRY_FIELDS).equals(current), "legacy entries do not re-encode to identity-log.bin");
  assert.ok(tamperedLegacy.equals(flipLast(legacy)), "tampered-legacy is not legacy with its last byte flipped");
  assert.ok(tampered.equals(flipLast(current)), "tampered is not the log with its last byte flipped");
  lines.push("identity: re-encoding the legacy entries reproduces identity-log.bin byte for byte; each tampered file is its log with the last byte flipped");

  for (const name of ["identity-tampered.bin", "identity-tampered-legacy.bin"]) {
    const bytes = name === "identity-tampered.bin" ? tampered : tamperedLegacy;
    const { entries } = decodeIdentity(bytes); // must still decode
    const why = expectRejection(() => replayIdentity(entries, recovery), "BrokenLink", 3);
    lines.push(`identity: ${name} decodes and is refused with ${why} (last signature byte flipped)`);
  }

  // The signature check alone also refuses it: the flipped byte is in entry 3's
  // ML-DSA half, so with the link check disabled the rejection must move there.
  identityChecks.link = false;
  try {
    const why = expectRejection(() => replayIdentity(decodeIdentity(tampered).entries, recovery), "BadSignature", 3);
    lines.push(`identity: with the link check disabled, identity-tampered.bin is still refused with ${why}`);
  } finally {
    identityChecks.link = true;
  }

  for (const [bytes, from, to] of [[legacy, 0x86, 0x87], [current, 0x87, 0x86]]) {
    const mixed = Buffer.from(bytes);
    assert.equal(mixed[1], from);
    mixed[1] = to;
    expectRejection(() => decodeIdentity(mixed), "Malformed");
  }
  lines.push("identity: reframing one entry (mixed 6/7 headers) is refused as Malformed in both directions");

  for (const header of [0x85, 0x88]) {
    const other = Buffer.from(current);
    other[1] = header;
    expectRejection(() => decodeIdentity(other), "Malformed");
  }
  const nonMinimal = concat(Buffer.from([0x84, 0x87, 0x18, 0x00]), current.subarray(3));
  expectRejection(() => decodeIdentity(nonMinimal), "Malformed");
  expectRejection(() => decodeIdentity(concat(current, Buffer.from([0x00]))), "Malformed");
  lines.push("identity: entry headers of 5 or 8, a non-shortest sequence integer and a trailing byte are refused as Malformed");

  // A revoked device cannot author anything later: re-sign nothing, just claim
  // the laptop signed a fifth entry by reusing entry 3's fields.
  const entries = decodeIdentity(current).entries;
  // A label smuggled into a Revoke has no field in the signed bytes, so only
  // the canonical re-encode can refuse it.
  const smuggled = encodeIdentity(entries, ENTRY_FIELDS);
  // From the end: signature (3-byte head + 3373), link (2 + 32), signer (2 + 32).
  const revokeLabelAt = smuggled.length - (3 + SIGNATURE_LEN) - (2 + 32) - (2 + 32) - 1;
  assert.equal(smuggled[revokeLabelAt], 0x60, "Revoke label is not at the computed offset");
  const withLabel = concat(smuggled.subarray(0, revokeLabelAt), Buffer.from([0x61, 0x78]), smuggled.subarray(revokeLabelAt + 1));
  expectRejection(() => decodeIdentity(withLabel), "Malformed");
  lines.push("identity: a non-empty label smuggled into the Revoke entry is refused as Malformed");

  const forged = { ...entries[3], sequence: 4n, signer: deviceId(laptop) };
  forged.link = identityLink(identitySignedBytes(entries[3].link, forged), forged.signature);
  expectRejection(() => replayIdentity([...entries, forged], recovery), "Unauthorised", 4);
  const recoverBySigner = { ...entries[1], tag: 4 };
  recoverBySigner.link = identityLink(identitySignedBytes(entries[0].link, recoverBySigner), recoverBySigner.signature);
  expectRejection(() => replayIdentity([entries[0], recoverBySigner], recovery), "Unauthorised", 1);
  lines.push("identity: an entry attributed to the revoked laptop, and a Recover signed by a device, are refused as Unauthorised");

  // The frozen tampered vectors flip a byte in the ML-DSA half only. These
  // derived entries break the Ed25519 half alone, with the link recomputed so
  // only the signature check can refuse them.
  const withSignature = (signature) => {
    const entry = { ...entries[3], signature };
    entry.link = identityLink(identitySignedBytes(entries[2].link, entry), signature);
    return [...entries.slice(0, 3), entry];
  };
  const flippedR = Buffer.from(entries[3].signature);
  flippedR[5] ^= 1;
  expectRejection(() => replayIdentity(withSignature(flippedR), recovery), "BadSignature", 3);
  const s = littleEndian(entries[3].signature.subarray(32, 64)) + ED25519_L;
  assert.ok(s < 1n << 256n);
  const malleated = Buffer.from(entries[3].signature);
  for (let i = 0; i < 32; i++) malleated[32 + i] = Number((s >> BigInt(8 * i)) & 0xffn);
  expectRejection(() => replayIdentity(withSignature(malleated), recovery), "BadSignature", 3);
  const signedEntry3 = bind(ENTRY_CONTEXT, identitySignedBytes(entries[2].link, entries[3]));
  const signer3 = [entries[0].payload, phone, laptop].find((key) => deviceId(key).equals(entries[3].signer));
  assert.ok(signer3, "entry 3's signer is not a known device");
  const plainMalleated = nodeVerify(null, signedEntry3,
    createPublicKey({ key: concat(ED25519_SPKI, signer3.subarray(0, 32)), format: "der", type: "spki" }),
    malleated.subarray(0, 64));
  assert.ok(nodeVerify(null, signedEntry3,
    createPublicKey({ key: concat(ED25519_SPKI, signer3.subarray(0, 32)), format: "der", type: "spki" }),
    entries[3].signature.subarray(0, 64)), "baseline Ed25519 half of entry 3 does not verify");
  lines.push(`identity: entry 3 with a flipped Ed25519 R byte, and with S+L (malleated, non-canonical S), is refused as BadSignature(3) (plain node:crypto on S+L: ${plainMalleated})`);

  for (const blocked of SMALL_ORDER) {
    const signed = Buffer.from(blocked);
    signed[31] |= 0x80;
    assert.ok(hasSmallOrder(blocked) && hasSmallOrder(signed));
  }
  for (const key of [recovery, phone, laptop]) assert.ok(!hasSmallOrder(key.subarray(0, 32)));
  lines.push(`identity: the ${SMALL_ORDER.length}-entry small-order blocklist matches with and without the sign bit; no vector key is on it`);

  // Constructed Ed25519 signatures that plain (cofactorless) verification
  // accepts and verify_strict refuses. Using the base point B as the public key
  // means the secret scalar is 1, so valid signatures can be forged here.
  const message = ascii("small-order probe");
  const B = Buffer.from("5866666666666666666666666666666666666666666666666666666666666666", "hex");
  const identityPoint = SMALL_ORDER[1];
  const scalar = (value) => {
    const out = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) out[i] = Number((value >> BigInt(8 * i)) & 0xffn);
    return out;
  };
  const challenge = (R, A) => littleEndian(createHash("sha512").update(concat(R, A, message)).digest()) % ED25519_L;
  const plain = (A, sig) => nodeVerify(null, message, createPublicKey({ key: concat(ED25519_SPKI, A), format: "der", type: "spki" }), sig);
  // A is the identity point: R = B, S = 1 satisfies [S]B = R + [k]A.
  const smallA = concat(B, scalar(1n));
  // R is the identity point, A = B: S = k satisfies [S]B = R + [k]B.
  const smallR = concat(identityPoint, scalar(challenge(identityPoint, B)));
  const honest = concat(B, scalar((1n + challenge(B, B)) % ED25519_L));
  assert.ok(plain(B, honest) && ed25519Strict(B, honest, message), "the forged baseline signature must verify");
  assert.ok(!ed25519Strict(identityPoint, smallA, message), "small-order public key accepted");
  assert.ok(!ed25519Strict(B, smallR, message), "small-order R accepted");
  const plainA = plain(identityPoint, smallA);
  const plainR = plain(B, smallR);
  lines.push(`identity: strict Ed25519 refuses a small-order public key and a small-order R (plain node:crypto accepts them: A=${plainA}, R=${plainR})`);
  return lines;
}

// ---------------------------------------------------------------------------
// §9 Epoch chains
// ---------------------------------------------------------------------------

const CHAIN_INFO = ascii("HIDE/0.6 epoch chain");
const EPOCH_PUBLIC_KEY_LEN = 1216;
const MAX_CHAIN_ENTRIES = 1_000_000n;
const EPOCH_BROKEN_OFFSET = 1261;

const epochLink = (previous, number, publicKey) =>
  sha256(CHAIN_INFO, previous, u64be(number), u64be(publicKey.length), publicKey);

function encodeEpochs(records) {
  const parts = [cborArray(records.length)];
  for (const record of records) {
    parts.push(cborArray(3), cborUint(record.number), cborBytes(record.publicKey), cborBytes(record.link));
  }
  return concat(...parts);
}

export function decodeEpochs(bytes) {
  const reader = new StrictReader(bytes);
  const count = reader.array();
  if (count > MAX_CHAIN_ENTRIES) throw new Rejection("TooManyEntries");
  const records = [];
  for (let i = 0n; i < count; i++) {
    if (reader.array() !== 3n) throw new Rejection("Malformed");
    const number = reader.uint();
    const publicKey = reader.bytestring();
    const link = reader.bytestring();
    if (link.length !== 32) throw new Rejection("Malformed");
    records.push({ number, publicKey, link });
  }
  reader.finish();
  if (!encodeEpochs(records).equals(bytes)) throw new Rejection("Malformed");
  return records;
}

export const epochChecks = { link: true };

export function verifyEpochs(records) {
  if (BigInt(records.length) > MAX_CHAIN_ENTRIES) throw new Rejection("TooManyEntries");
  let previous = ZERO32;
  records.forEach((record, index) => {
    if (record.number !== BigInt(index)) throw new Rejection("BrokenLink", index);
    if (record.publicKey.length !== EPOCH_PUBLIC_KEY_LEN) throw new Rejection("WrongKeyLength", index);
    if (epochChecks.link && !epochLink(previous, record.number, record.publicKey).equals(record.link)) {
      throw new Rejection("BrokenHash", index);
    }
    previous = record.link;
  });
  return previous;
}

async function verifyEpochChain(read) {
  const lines = [];
  const chain = await read("epoch-chain.bin");
  const broken = await read("epoch-broken.bin");
  const key1 = await read("epoch-public-key-1.bin");
  const records = decodeEpochs(chain);
  assert.equal(records.length, 3);
  const head = verifyEpochs(records);
  assert.ok(records[1].publicKey.equals(key1), "epoch-public-key-1.bin is not epoch 1's key");
  lines.push(`epoch: epoch-chain.bin is a valid chain of 3 epochs (head ${hex(head).slice(0, 16)}…); epoch-public-key-1.bin is epoch 1's 1216-byte key`);

  const expected = Buffer.from(chain);
  expected[EPOCH_BROKEN_OFFSET] ^= 1;
  assert.ok(broken.equals(expected), "epoch-broken.bin is not the chain with byte 1261 flipped");
  // Byte 1261 lies inside epoch 1's public key, not in any framing.
  const brokenRecords = decodeEpochs(broken);
  assert.ok(!brokenRecords[1].publicKey.equals(key1));
  assert.ok(brokenRecords[1].link.equals(records[1].link));
  const why = expectRejection(() => verifyEpochs(brokenRecords), "BrokenHash", 1);
  lines.push(`epoch: epoch-broken.bin (byte ${EPOCH_BROKEN_OFFSET} of epoch 1's key flipped) decodes and is refused with ${why}`);
  return lines;
}

// ---------------------------------------------------------------------------
// §10 Transparency (RFC 6962)
// ---------------------------------------------------------------------------

const MAX_PROOF_LEN = 64;
const U64_MAX = 0xffffffffffffffffn;
const nodeHash = (left, right) => sha256(Buffer.from([0x01]), left, right);

/// Largest power of two strictly below n (n > 1), from the bit length: never a
/// loop over the value.
function largestPowerOfTwoBelow(n) {
  assert.ok(n > 1n && n <= U64_MAX);
  return 1n << BigInt((n - 1n).toString(2).length - 1);
}

export const transparencyChecks = { newRoot: true };

export function verifyInclusion({ index, size, path }, leaf, root) {
  if (path.length > MAX_PROOF_LEN) throw new Rejection("ProofTooLong");
  if (index >= size) throw new Rejection("OutOfRange");
  const turns = [];
  // Each step at least halves `size`, so this runs at most 64 times; the bound
  // is the bit width, asserted rather than assumed.
  while (size > 1n) {
    assert.ok(turns.length < 64);
    const split = largestPowerOfTwoBelow(size);
    if (index < split) {
      turns.push(true);
      size = split;
    } else {
      turns.push(false);
      index -= split;
      size -= split;
    }
  }
  if (turns.length !== path.length) throw new Rejection("BadProof", "path length");
  let hash = leaf;
  turns.reverse().forEach((wentLeft, i) => {
    hash = wentLeft ? nodeHash(hash, path[i]) : nodeHash(path[i], hash);
  });
  if (!hash.equals(root)) throw new Rejection("BadProof", "root mismatch");
}

export function verifyConsistency({ oldSize, newSize, path }, oldRoot, newRoot) {
  if (path.length > MAX_PROOF_LEN) throw new Rejection("ProofTooLong");
  if (oldSize === 0n || oldSize > newSize) throw new Rejection("NotAPrefix");
  if (oldSize === newSize) {
    if (path.length === 0 && oldRoot.equals(newRoot)) return;
    throw new Rejection("BadProof", "equal sizes");
  }
  const turns = [];
  let complete = true;
  while (oldSize !== newSize) {
    assert.ok(turns.length < 64);
    const split = largestPowerOfTwoBelow(newSize);
    if (oldSize <= split) {
      turns.push(true);
      newSize = split;
    } else {
      turns.push(false);
      oldSize -= split;
      newSize -= split;
      complete = false;
    }
  }
  if (path.length !== turns.length + (complete ? 0 : 1)) throw new Rejection("BadProof", "path length");
  let cursor = 0;
  const seed = complete ? oldRoot : path[cursor++];
  let oldHash = seed;
  let newHash = seed;
  for (const wentLeft of turns.reverse()) {
    const sibling = path[cursor++];
    if (wentLeft) {
      newHash = nodeHash(newHash, sibling);
    } else {
      oldHash = nodeHash(sibling, oldHash);
      newHash = nodeHash(sibling, newHash);
    }
  }
  if (!oldHash.equals(oldRoot)) throw new Rejection("BadProof", "old root mismatch");
  if (transparencyChecks.newRoot && !newHash.equals(newRoot)) throw new Rejection("BadProof", "new root mismatch");
}

function hashes(bytes) {
  assert.equal(bytes.length % 32, 0);
  const out = [];
  for (let i = 0; i < bytes.length; i += 32) out.push(bytes.subarray(i, i + 32));
  return out;
}

async function verifyTransparency(read) {
  const lines = [];
  const leaf = await read("leaf.bin");
  const other = await read("other-leaf.bin");
  const root = await read("tree-root.bin");
  const root5 = await read("root-at-5.bin");
  const rewritten = await read("rewritten-root.bin");
  for (const value of [leaf, other, root, root5, rewritten]) assert.equal(value.length, 32);
  const inclusion = { index: 3n, size: 8n, path: hashes(await read("inclusion-path.bin")) };
  const consistency = { oldSize: 5n, newSize: 8n, path: hashes(await read("consistency-path.bin")) };
  assert.equal(inclusion.path.length, 3);
  assert.equal(consistency.path.length, 4);

  verifyInclusion(inclusion, leaf, root);
  lines.push("transparency: leaf.bin is entry 3 of 8 under tree-root.bin (3-hash path)");
  const whyLeaf = expectRejection(() => verifyInclusion(inclusion, other, root), "BadProof", "root mismatch");
  lines.push(`transparency: other-leaf.bin at index 3 is refused with ${whyLeaf}`);

  verifyConsistency(consistency, root5, root);
  lines.push("transparency: root-at-5.bin is a prefix of tree-root.bin (5 -> 8, 4-hash path)");
  const whyRewrite = expectRejection(() => verifyConsistency(consistency, root5, rewritten), "BadProof", "new root mismatch");
  lines.push(`transparency: rewritten-root.bin is refused with ${whyRewrite} (the old root still reconstructs)`);

  // Loops are bounded by bit width even for the largest sizes.
  expectRejection(() => verifyInclusion({ index: U64_MAX - 1n, size: U64_MAX, path: [] }, leaf, root), "BadProof", "path length");
  expectRejection(() => verifyConsistency({ oldSize: 1n, newSize: U64_MAX, path: [] }, root5, root), "BadProof", "path length");
  lines.push("transparency: proofs claiming size 2^64-1 terminate (bit-width bound) and are refused on path length");
  return lines;
}

// ---------------------------------------------------------------------------

export async function verifySubsystems(vectorsDirUrl) {
  const dir = new URL("subsystems/", vectorsDirUrl);
  const read = async (name) => Buffer.from(await readFile(new URL(name, dir)));
  return [
    ...(await verifyIdentity(read)),
    ...(await verifyEpochChain(read)),
    ...(await verifyTransparency(read)),
  ];
}

if (process.argv[1] && resolve(fileURLToPath(import.meta.url)) === resolve(process.argv[1])) {
  const lines = await verifySubsystems(new URL("../vectors/", import.meta.url));
  for (const line of lines) console.log(`PASS ${line}`);
  console.log(`subsystems: ${lines.length} checks passed`);
}
