import { invoke } from "@tauri-apps/api/core";

/**
 * The only place the frontend talks to the cryptographic core. Key material
 * never crosses this boundary: passphrases go in, results come out.
 */

export type KeyPair = {
  public_path: string;
  secret_path: string;
  armored_public: string;
  protected: boolean;
};

export type Description = {
  kind: string;
  detail: string;
  warning: string | null;
};

export function generateKeys(
  directory: string,
  name: string,
  passphrase: string | null,
): Promise<KeyPair> {
  return invoke("generate_keys", { directory, name, passphrase });
}

export function encryptFile(
  input: string,
  recipients: string[],
  output: string,
): Promise<string> {
  return invoke("encrypt_file", { input, recipients, output });
}

export function decryptFile(
  input: string,
  secret: string,
  passphrase: string | null,
  output: string,
): Promise<string> {
  return invoke("decrypt_file", { input, secret, passphrase, output });
}

export function sealMessage(
  message: string,
  recipients: string[],
): Promise<string> {
  return invoke("seal_message", { message, recipients });
}

export function unsealMessage(
  armored: string,
  secret: string,
  passphrase: string | null,
): Promise<string> {
  return invoke("unseal_message", { armored, secret, passphrase });
}

export function describe(path: string): Promise<Description> {
  return invoke("describe", { path });
}

export function readPublicArmor(path: string): Promise<string> {
  return invoke("read_public_armor", { path });
}

/** Empty unless this is a portable build, which keeps keys beside the app. */
export function defaultKeyDirectory(): Promise<string> {
  return invoke("default_key_directory");
}

export function isPortable(): Promise<boolean> {
  return invoke("is_portable");
}

/** Rust returns plain strings for failures; anything else is a real bug. */
export function messageOf(error: unknown): string {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  return "Something went wrong.";
}
