/**
 * HIDE — encrypt to a person, not to a key.
 *
 * EXPERIMENTAL AND UNAUDITED. Do not protect data you cannot afford to lose or
 * expose. A successful decryption proves the data was not altered; it does
 * *not* prove who created it.
 *
 * ```ts
 * import { SecretKey, encrypt, decrypt } from "hide-protocol";
 *
 * using secret = SecretKey.generate();
 * const box = encrypt(Buffer.from("hello"), [secret.publicKey()]);
 * console.log(decrypt(box, secret).data.toString());
 * ```
 */

import {
  ERR_AUTHENTICATION,
  ERR_INVALID_ARGUMENT,
  ERR_MALFORMED,
  ERR_NOT_A_KEY,
  ERR_NO_MATCHING_RECIPIENT,
  ERR_TOO_LARGE,
  ERR_WRONG_PASSPHRASE,
  KEY_PROTECTED,
  MIN_PASSPHRASE_LEN,
  OK,
  PUBLIC_KEY_LEN,
  fns,
  koffi,
} from "./binding.js";

export { MIN_PASSPHRASE_LEN, PUBLIC_KEY_LEN };
export const version: string = fns.version();

export class HideError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}
/** The data was altered, or is not a HIDE container. */
export class AuthenticationError extends HideError {}
/** The passphrase is wrong, or the key file was modified. */
export class WrongPassphraseError extends HideError {}
/** This key was not one of the recipients. */
export class NoMatchingRecipientError extends HideError {}
/** The bytes are not a HIDE key. */
export class NotAKeyError extends HideError {}

function check(code: number): void {
  if (code === OK) return;
  const message = fns.errorMessage(code);
  switch (code) {
    case ERR_WRONG_PASSPHRASE:
      throw new WrongPassphraseError(message);
    case ERR_NOT_A_KEY:
      throw new NotAKeyError(message);
    case ERR_NO_MATCHING_RECIPIENT:
      throw new NoMatchingRecipientError(message);
    case ERR_AUTHENTICATION:
    case ERR_MALFORMED:
      throw new AuthenticationError(message);
    case ERR_INVALID_ARGUMENT:
    case ERR_TOO_LARGE:
      throw new RangeError(message);
    default:
      throw new HideError(message);
  }
}

type NativeBuffer = { data: unknown; len: number; capacity: number };

function emptyBuffer(): NativeBuffer {
  return { data: null, len: 0, capacity: 0 };
}

/** Copies a native buffer into a Node Buffer, then frees the original. */
function take(buffer: NativeBuffer): Buffer {
  try {
    if (!buffer.data || buffer.len === 0) return Buffer.alloc(0);
    return Buffer.from(koffi.decode(buffer.data, koffi.array("uint8_t", buffer.len)));
  } finally {
    fns.bufferFree(buffer);
  }
}

/** Metadata arrives as length-prefixed UTF-8; empty means absent. */
function takeText(buffer: NativeBuffer): string | undefined {
  const bytes = take(buffer);
  return bytes.length > 0 ? bytes.toString("utf8") : undefined;
}

/**
 * A secret key. The bytes stay inside the native library and are never exposed
 * to JavaScript. Release it with `close()`, `using`, or let the finalizer run.
 */
export class SecretKey {
  #handle: unknown;
  static #registry = new FinalizationRegistry<unknown>((handle) => {
    fns.secretKeyFree(handle);
  });

  private constructor(handle: unknown) {
    this.#handle = handle;
    SecretKey.#registry.register(this, handle, this);
  }

  static generate(): SecretKey {
    const secret = [null];
    const publicKey = emptyBuffer();
    check(fns.keypairGenerate(secret, publicKey));
    fns.bufferFree(publicKey);
    return new SecretKey(secret[0]);
  }

  /** Loads a key file. A protected key without its passphrase fails. */
  static load(data: Uint8Array, passphrase?: string): SecretKey {
    const secret = [null];
    check(fns.secretKeyOpen(data, data.length, passphrase ?? null, secret));
    return new SecretKey(secret[0]);
  }

  publicKey(): Buffer {
    const out = emptyBuffer();
    check(fns.secretKeyPublic(this.#alive(), out));
    return take(out);
  }

  /**
   * Seals this key with a passphrase, for writing to disk. A forgotten
   * passphrase cannot be recovered: there is no escrow.
   */
  protect(passphrase: string): Buffer {
    if (passphrase.length < MIN_PASSPHRASE_LEN) {
      throw new RangeError(
        `the passphrase must be at least ${MIN_PASSPHRASE_LEN} characters`,
      );
    }
    const out = emptyBuffer();
    check(fns.secretKeyProtect(this.#alive(), passphrase, out));
    return take(out);
  }

  close(): void {
    if (this.#handle) {
      SecretKey.#registry.unregister(this);
      fns.secretKeyFree(this.#handle);
      this.#handle = null;
    }
  }

  [Symbol.dispose](): void {
    this.close();
  }

  /** Never render key material, not even a fingerprint of it. */
  toJSON(): string {
    return "[hide.SecretKey]";
  }

  #alive(): unknown {
    if (!this.#handle) throw new TypeError("this key has been closed");
    return this.#handle;
  }

  /** @internal */
  get handle(): unknown {
    return this.#alive();
  }
}

/** A verified payload. Receiving this object means it authenticated. */
export interface Decrypted {
  data: Buffer;
  filename?: string;
  mediaType?: string;
}

export interface EncryptOptions {
  filename?: string;
  mediaType?: string;
}

/** Encrypts for 1..64 recipient public keys. */
export function encrypt(
  plaintext: Uint8Array,
  recipients: readonly Uint8Array[],
  options: EncryptOptions = {},
): Buffer {
  if (recipients.length < 1 || recipients.length > 64) {
    throw new RangeError("there must be between 1 and 64 recipients");
  }
  const joined = Buffer.alloc(recipients.length * PUBLIC_KEY_LEN);
  recipients.forEach((key, index) => {
    if (key.length !== PUBLIC_KEY_LEN) {
      throw new RangeError(
        `a public key is ${PUBLIC_KEY_LEN} bytes, got ${key.length}`,
      );
    }
    joined.set(key, index * PUBLIC_KEY_LEN);
  });

  const out = emptyBuffer();
  check(
    fns.encrypt(
      plaintext,
      plaintext.length,
      joined,
      recipients.length,
      options.filename ?? null,
      options.mediaType ?? null,
      out,
    ),
  );
  return take(out);
}

/**
 * Decrypts and verifies. Nothing is returned unless the whole payload
 * authenticates.
 *
 * The filename is attacker-controlled: never use it to choose an output path.
 */
export function decrypt(container: Uint8Array, secret: SecretKey): Decrypted {
  const out = emptyBuffer();
  const filename = emptyBuffer();
  const mediaType = emptyBuffer();
  check(
    fns.decrypt(container, container.length, secret.handle, out, filename, mediaType),
  );
  return {
    data: take(out),
    filename: takeText(filename),
    mediaType: takeText(mediaType),
  };
}

/** Renders a public key as pasteable text. */
export function armorPublicKey(publicKey: Uint8Array): string {
  const out = emptyBuffer();
  check(fns.publicKeyArmor(publicKey, publicKey.length, out));
  return takeText(out) ?? "";
}

export function dearmorPublicKey(text: string): Buffer {
  const out = emptyBuffer();
  check(fns.publicKeyDearmor(text, out));
  return take(out);
}

/** Reports `"raw"` or `"protected"` without needing the passphrase. */
export function inspectKey(data: Uint8Array): "raw" | "protected" {
  const kind = [0];
  check(fns.inspectKey(data, data.length, kind));
  return kind[0] === KEY_PROTECTED ? "protected" : "raw";
}
