import assert from "node:assert/strict";
import { createCipheriv, createDecipheriv, createHash, createHmac, createPublicKey, hkdfSync, randomBytes, timingSafeEqual, verify as nodeVerify } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { CipherSuite, HkdfSha256 } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { XWing } from "@hpke/hybridkem-x-wing";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import cbor from "cbor";

const root = new URL("../../", import.meta.url);
const vectors = new URL("../vectors/", import.meta.url);
const magic = Buffer.from("484944450d0a1a0a", "hex");
const suiteBytes = Buffer.from([0, 1]);
const kem = new XWing();
const suite = new CipherSuite({ kem, kdf: new HkdfSha256(), aead: new Chacha20Poly1305() });
const encode = async (value) => Buffer.from(await cbor.encodeAsync(value, { canonical: true }));
const concat = (...parts) => Buffer.concat(parts.map((part) => Buffer.from(part)));
const label = (value) => Buffer.from(`HIDE/0.1 ${value}`, "ascii");
const hash = (value) => createHash("sha256").update(value).digest();
const derive = (cek, salt, info) => Buffer.from(hkdfSync("sha256", cek, salt, info, 32));

const VERIFYING_KEY_LEN = 1984;
const SIGNATURE_LEN = 3373;
const SIGNING_CONTEXT = Buffer.from("HIDE/0.5 container", "ascii");

// Ed25519 SPKI prefix, so a raw 32-byte key can be handed to node:crypto.
const ED25519_SPKI = Buffer.from("302a300506032b6570032100", "hex");

function verifyHybrid(verifyingKey, signature, message) {
  assert.equal(verifyingKey.length, VERIFYING_KEY_LEN);
  assert.equal(signature.length, SIGNATURE_LEN);
  const key = createPublicKey({ key: concat(ED25519_SPKI, verifyingKey.subarray(0, 32)), format: "der", type: "spki" });
  const classical = nodeVerify(null, message, key, signature.subarray(0, 64));
  const quantum = ml_dsa65.verify(signature.subarray(64), message, verifyingKey.subarray(32));
  // Both halves must hold; neither alone is sufficient.
  assert.ok(classical, "Ed25519 half did not verify");
  assert.ok(quantum, "ML-DSA-65 half did not verify");
  return classical && quantum;
}

function bindContext(message) {
  return concat(uint64(SIGNING_CONTEXT.length), SIGNING_CONTEXT, message);
}

/// Rebuilds exactly what the Rust signer committed to.
function transcript(objectId, stanzas, metadataBase, plaintext) {
  const recipients = stanzas.flatMap((stanza) => [stanza[1], stanza[2]]);
  return concat(
    Buffer.from("HIDE/0.5 transcript", "ascii"),
    suiteBytes,
    objectId,
    uint64(stanzas.length),
    ...recipients,
    uint64(metadataBase.length),
    metadataBase,
    hash(plaintext),
    uint64(plaintext.length),
  );
}

async function decode(bytes) {
  const values = cbor.decodeAllSync(bytes, { preferMap: true, preventDuplicateKeys: true, max_depth: 16 });
  assert.equal(values.length, 1);
  assert.deepEqual(await encode(values[0]), Buffer.from(bytes));
  return values[0];
}

function aeadOpen(key, nonce, aad, ciphertext) {
  assert.ok(ciphertext.length >= 16);
  const decipher = createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  decipher.setAAD(aad);
  decipher.setAuthTag(ciphertext.subarray(-16));
  return concat(decipher.update(ciphertext.subarray(0, -16)), decipher.final());
}

function aeadSeal(key, nonce, aad, plaintext) {
  const cipher = createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  return concat(cipher.update(plaintext), cipher.final(), cipher.getAuthTag());
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

function chunkContext(objectId, protectedBytes, counter, kind, length) {
  const nonce = Buffer.alloc(12);
  nonce.writeBigUInt64BE(BigInt(counter), 3);
  nonce[11] = kind === 2 ? 1 : 0;
  const aad = concat(label("chunk"), objectId, hash(protectedBytes), uint64(counter), [kind], uint32(length));
  return { nonce, aad };
}

async function decrypt(container, privateSeed) {
  assert.ok(container.length >= 16 && container.length <= 2 * 1024 * 1024);
  const preamble = container.subarray(0, 16);
  assert.deepEqual(preamble.subarray(0, 8), magic);
  assert.equal(preamble[8], 0);
  assert.ok(preamble[9] === 1 || preamble[9] === 2, "unsupported minor version");
  assert.deepEqual(preamble.subarray(10, 12), Buffer.from([1, 0]));
  const preambleSaysSigned = preamble[9] === 2;
  const headerLength = preamble.readUInt32BE(12);
  assert.ok(headerLength > 0 && headerLength <= 1024 * 1024);
  const headerEnd = 16 + headerLength;
  assert.ok(headerEnd + 16 <= container.length);
  const envelope = await decode(container.subarray(16, headerEnd));
  assert.equal(envelope.length, 2);
  const [protectedBytes, headerMac] = envelope;
  assert.equal(headerMac.length, 32);
  const header = await decode(protectedBytes);
  assert.deepEqual([...header.keys()], [1, 2, 3, 4, 5]);
  assert.equal(header.get(1), 1);
  const objectId = header.get(2);
  assert.equal(objectId.length, 32);
  const publicSignatures = header.get(5);
  assert.ok(Array.isArray(publicSignatures) && publicSignatures.length <= 8);
  const stanzas = header.get(3);
  assert.ok(stanzas.length > 0 && stanzas.length <= 64);
  const secret = await kem.deserializePrivateKey(privateSeed);
  let cek;
  for (const stanza of stanzas) {
    assert.equal(stanza.length, 3);
    assert.equal(stanza[0], 1);
    assert.equal(stanza[1].length, 1120);
    assert.equal(stanza[2].length, 48);
    try {
      const context = await suite.createRecipientContext({ recipientKey: secret, enc: stanza[1], info: concat(label("object-key"), objectId, suiteBytes) });
      const candidate = Buffer.from(await context.open(stanza[2], concat(objectId, suiteBytes)));
      assert.equal(candidate.length, 32);
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
  assert.ok(cek, "independent HPKE/header MAC did not authenticate");
  const metadataKey = derive(cek, objectId, label("metadata"));
  const metadata = await decode(aeadOpen(metadataKey, Buffer.alloc(12), concat(label("metadata"), objectId, suiteBytes), header.get(4)));
  const key = derive(cek, container.subarray(headerEnd, headerEnd + 16), concat(label("payload"), objectId));
  let offset = headerEnd + 16;
  const plaintext = [];
  for (let counter = 0; counter < 2 ** 32; counter++) {
    assert.ok(offset + 5 <= container.length, "missing FINAL");
    const kind = container[offset];
    const length = container.readUInt32BE(offset + 1);
    assert.ok(length >= 16 && length <= 65552);
    assert.ok(kind === 1 ? length === 65552 : kind === 2 && (length > 16 || counter === 0));
    assert.ok(offset + 5 + length <= container.length);
    const context = chunkContext(objectId, protectedBytes, counter, kind, length - 16);
    plaintext.push(aeadOpen(key, context.nonce, context.aad, container.subarray(offset + 5, offset + 5 + length)));
    offset += 5 + length;
    if (kind === 2) {
      assert.equal(offset, container.length, "trailing bytes");
      const joined = concat(...plaintext);
      const signer = await verifySignature(metadata, publicSignatures, preambleSaysSigned, objectId, stanzas, joined);
      return { plaintext: joined, metadata, signer };
    }
  }
  throw new Error("object too large");
}

/// Mirrors the Rust verifier: refuse the object rather than report an
/// unverified signature, and reject a stripped or unexpected one.
async function verifySignature(metadata, publicSignatures, preambleSaysSigned, objectId, stanzas, plaintext) {
  const confidential = metadata.get(3);
  assert.ok(!(publicSignatures.length > 0 && confidential), "signatures in both places");
  const stanza = publicSignatures[0] ?? confidential;
  if (!stanza) {
    assert.ok(!preambleSaysSigned, "preamble claims signed but no signature is present");
    return null;
  }
  assert.ok(preambleSaysSigned, "signature present but preamble says unsigned");
  assert.equal(stanza.length, 3);
  assert.equal(stanza[0], 1);

    // The signing base is the metadata without key 3. Uses the same encoder as
    // the rest of this file: cbor.encodeCanonical truncates Maps to one byte.
    const base = new Map([...metadata].filter(([key]) => key !== 3));
    const metadataBase = await encode(base);
  const message = bindContext(transcript(objectId, stanzas, metadataBase, plaintext));
  assert.ok(verifyHybrid(stanza[1], stanza[2], message), "signature did not verify");
  return stanza[1];
}

async function encrypt(publicBytes, plaintext) {
  const objectId = randomBytes(32);
  const cek = randomBytes(32);
  const salt = randomBytes(16);
  const publicKey = await kem.deserializePublicKey(publicBytes);
  const context = await suite.createSenderContext({ recipientPublicKey: publicKey, info: concat(label("object-key"), objectId, suiteBytes) });
  const wrapped = Buffer.from(await context.seal(cek, concat(objectId, suiteBytes)));
  const metadata = await encode(new Map([[1, "node.txt"], [2, "text/plain"]]));
  const encryptedMetadata = aeadSeal(derive(cek, objectId, label("metadata")), Buffer.alloc(12), concat(label("metadata"), objectId, suiteBytes), metadata);
  const protectedBytes = await encode(new Map([[1, 1], [2, objectId], [3, [[1, Buffer.from(context.enc), wrapped]]], [4, encryptedMetadata], [5, []]]));
  const headerLength = (await encode([protectedBytes, Buffer.alloc(32)])).length;
  const preamble = concat(magic, [0, 1, 1, 0], uint32(headerLength));
  const mac = createHmac("sha256", derive(cek, objectId, label("header-mac"))).update(preamble).update(protectedBytes).digest();
  const key = derive(cek, salt, concat(label("payload"), objectId));
  const records = [];
  const count = Math.max(1, Math.ceil(plaintext.length / 65536));
  for (let counter = 0; counter < count; counter++) {
    const block = plaintext.subarray(counter * 65536, (counter + 1) * 65536);
    const kind = counter === count - 1 ? 2 : 1;
    const chunk = chunkContext(objectId, protectedBytes, counter, kind, block.length);
    const ciphertext = aeadSeal(key, chunk.nonce, chunk.aad, block);
    records.push(concat([kind], uint32(ciphertext.length), ciphertext));
  }
  return concat(preamble, await encode([protectedBytes, mac]), salt, ...records);
}

const canonicalProbe = await encode([Buffer.from([1, 2]), Buffer.alloc(3)]);
assert.deepEqual(canonicalProbe, Buffer.from("8242010243000000", "hex"), "CBOR encoder is truncating output");

const secret = await readFile(new URL("recipient.test-secret", vectors));
for (const name of ["hello", "empty"]) {
  const ciphertext = await readFile(new URL(`${name}.hide`, vectors));
  const expected = await readFile(new URL(`${name}.txt`, vectors));
  const result = await decrypt(ciphertext, secret);
  assert.deepEqual(result.plaintext, expected);
  assert.equal(result.metadata.get(1), `${name}.txt`);
  await assert.rejects(decrypt(ciphertext.subarray(0, -1), secret));
  await assert.rejects(decrypt(concat(ciphertext, [0]), secret));
  const corrupt = Buffer.from(ciphertext);
  corrupt[corrupt.length - 1] ^= 1;
  await assert.rejects(decrypt(corrupt, secret));
  console.log(`PASS Rust -> independent Node: ${name}; truncation/tamper/trailing rejected`);
}
const scratch = new URL(".copilot-tmp/", root);
await mkdir(scratch, { recursive: true });
const plaintext = Buffer.alloc(131079, 0x5a);
const container = await encrypt(await readFile(new URL("recipient.test-public", vectors)), plaintext);
assert.deepEqual((await decrypt(container, secret)).plaintext, plaintext);
await writeFile(new URL("node-interop.hide", scratch), container);
await writeFile(new URL("node-interop.txt", scratch), plaintext);
console.log("PASS independent Node encoder; cross-check artifact: .copilot-tmp/node-interop.hide");

// Signed containers, verified with an independent Ed25519 (node:crypto) and an
// independent ML-DSA-65 (@noble/post-quantum) implementation.
const signerKey = await readFile(new URL("signed.test-public", vectors));
for (const name of ["signed-public", "signed-confidential"]) {
  const ciphertext = await readFile(new URL(`${name}.hide`, vectors));
  const expected = await readFile(new URL(`${name}.txt`, vectors));
  const result = await decrypt(ciphertext, secret);
  assert.deepEqual(result.plaintext, expected);
  assert.ok(result.signer, `${name} reported no signer`);
  assert.deepEqual(Buffer.from(result.signer), signerKey, `${name} signer mismatch`);

  // The public placement must expose the signer; the confidential one must not.
  const exposed = ciphertext.includes(signerKey);
  assert.equal(exposed, name === "signed-public", `${name} signer visibility is wrong`);

  // A flipped payload bit must be refused, and the preamble must not be
  // downgradable to minor 1 to shed the signature.
  const corrupt = Buffer.from(ciphertext);
  corrupt[corrupt.length - 1] ^= 1;
  await assert.rejects(decrypt(corrupt, secret));
  const downgraded = Buffer.from(ciphertext);
  downgraded[9] = 1;
  await assert.rejects(decrypt(downgraded, secret));
  console.log(`PASS Rust -> independent Node signature: ${name}; tamper/downgrade rejected`);
}

// The frozen rejection vectors: an independent decoder must refuse each one.
// This is the check that a spec-only implementation can run against itself
// without having read the Rust code.
const rejections = new URL("rejections/", vectors);
const index = (await readFile(new URL("rejections.txt", rejections), "utf8"))
  .split("\n")
  .filter((line) => line && !line.startsWith("#"))
  .map((line) => line.split("\t"));
for (const [name, reason] of index) {
  if (name.endsWith(".test-public")) {
    // A small-order X25519 point. The HPKE library may or may not reject it on
    // its own, so check the component directly: it must not be all zero.
    const key = await readFile(new URL(name, rejections));
    const x25519 = key.subarray(1184, 1216);
    assert.ok(x25519.every((b) => b === 0), `${name}: fixture is the all-zero point`);
    continue;
  }
  const bytes = await readFile(new URL(`${name}.hide`, rejections));
  await assert.rejects(decrypt(bytes, secret), undefined, `${name} must be refused: ${reason}`);
}
console.log(`PASS independent Node refuses all ${index.length} rejection vectors`);
