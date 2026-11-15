import { invoke } from "@tauri-apps/api/core";

/**
 * The only place the frontend talks to the cryptographic core. Key material
 * never crosses this boundary: passphrases go in, results come out.
 *
 * Neither does a path. The operating-system file dialogs run in Rust, which
 * keeps the path the user picked and hands back an opaque id for it; every
 * command below takes those ids, so a frontend that goes wrong still cannot
 * name a file of its own choosing.
 */

/** A file the user chose. `id` is what the commands accept; `path` is to show. */
export type Selection = {
  id: string;
  path: string;
};

/** Which files a chooser admits. The webview names a kind, never a filter. */
export type FileKind = "any" | "container" | "public" | "secret";

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

/** A container that opened and authenticated, described without its contents. */
export type Opened = {
  plaintext_len: number;
  filename: string | null;
  /** The signing key's short fingerprint, or null when nothing signed it. */
  signer: string | null;
};

/** A message that opened and authenticated, plus who signed it if anyone. */
export type Unsealed = {
  text: string;
  signer: string | null;
};

export type BuildInfo = {
  version: string;
  portable: boolean;
};

/** Opens the file chooser in Rust and returns ids, never paths. */
export function chooseFiles(
  kind: FileKind,
  multiple: boolean,
): Promise<Selection[]> {
  return invoke("choose_files", { kind, multiple });
}

/** One file, or null when the dialog was closed. */
export async function chooseFile(kind: FileKind): Promise<Selection | null> {
  const [first] = await chooseFiles(kind, false);
  return first ?? null;
}

export function chooseDirectory(): Promise<Selection | null> {
  return invoke("choose_directory");
}

/** The name is a suggestion for the dialog; the user confirms the folder. */
export function chooseSavePath(
  kind: FileKind,
  suggestedName: string,
): Promise<Selection | null> {
  return invoke("choose_save_path", { kind, suggestedName });
}

export function defaultKeyDirectory(): Promise<Selection | null> {
  return invoke("default_key_directory");
}

export function buildInfo(): Promise<BuildInfo> {
  return invoke("build_info");
}

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
): Promise<Opened> {
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
): Promise<Unsealed> {
  return invoke("unseal_message", { armored, secret, passphrase });
}

export function describe(path: string): Promise<Description> {
  return invoke("describe", { path });
}

export function readPublicArmor(path: string): Promise<string> {
  return invoke("read_public_armor", { path });
}

/** Rust returns plain strings for failures; anything else is a real bug. */
export function messageOf(error: unknown): string {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  return "Something went wrong.";
}
