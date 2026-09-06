import assert from "node:assert/strict";
import { test } from "node:test";

import {
  AuthenticationError,
  NoMatchingRecipientError,
  PUBLIC_KEY_LEN,
  SecretKey,
  WrongPassphraseError,
  armorPublicKey,
  dearmorPublicKey,
  decrypt,
  encrypt,
  inspectKey,
} from "./index.js";

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
