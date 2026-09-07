import assert from "node:assert/strict";
import { test } from "node:test";

import {
  AuthenticationError,
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
  verifyConsistency,
  verifyEpochChain,
  verifyIdentity,
  verifyInclusion,
} from "./index.js";
import {
  consistencyPath,
  epochBroken,
  epochChain,
  epochPublicKey1,
  identityDeviceLaptop,
  identityDevicePhone,
  identityHead as identityHeadFixture,
  identityLog,
  identityRecovery,
  identityTampered,
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
const CONTEXT = Buffer.from("HIDE/0.5 node test");
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
  const spent = new SpentNonces();
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
  const spent = new SpentNonces();
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
