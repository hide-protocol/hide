import assert from "node:assert/strict";
import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { CipherSuite, HkdfSha256 } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { XWing } from "@hpke/hybridkem-x-wing";
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
  assert.deepEqual(preamble.subarray(8, 12), Buffer.from([0, 1, 1, 0]));
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
  assert.deepEqual(header.get(5), []);
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
      return { plaintext: concat(...plaintext), metadata };
    }
  }
  throw new Error("object too large");
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
